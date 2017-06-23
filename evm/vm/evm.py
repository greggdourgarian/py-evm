from __future__ import absolute_import

import collections

import rlp

from evm.exceptions import (
    ValidationError,
)
from evm.validation import (
    validate_vm_block_ranges,
    validate_uint256,
    validate_word,
)

from evm.rlp.headers import (
    BlockHeader,
)

from evm.utils.db import (
    make_block_number_to_hash_lookup_key,
)
from evm.utils.blocks import (
    persist_block_to_db,
)
from evm.utils.ranges import (
    range_sort_fn,
    find_range,
)

from evm.state import State


class EVM(object):
    """
    An EVM is a combination of one or more VM classes.  Each VM is associated
    with a range of blocks.  The EVM class acts as a wrapper around these other
    VM classes, delegating operations to the appropriate VM depending on the
    current block number.
    """
    db = None
    header = None

    vms_by_range = None

    def __init__(self, header):
        if self.db is None:
            raise ValueError("MetaEVM must be configured with a db")

        if not self.vms_by_range:
            raise ValueError("MetaEVM must be configured with block ranges")

        self.header = header

    @classmethod
    def configure(cls, name=None, vm_block_ranges=None, db=None):
        if vm_block_ranges is None:
            vms_by_range = cls.vms_by_range
        else:
            # Extract the block ranges for the provided EVMs
            if len(vm_block_ranges) == 1:
                # edge case for a single range.
                ranges = [vm_block_ranges[0][0]]
            else:
                raw_ranges, _ = zip(*vm_block_ranges)
                ranges = tuple(sorted(raw_ranges, key=range_sort_fn))

            # Validate that the block ranges define a continuous range of block
            # numbers with no gaps.
            validate_vm_block_ranges(ranges)

            # Organize the EVM classes by their respected ranges
            vms_by_range = collections.OrderedDict(
                (range, vm)
                for range, vm
                in vm_block_ranges
            )

        if name is None:
            name = cls.__name__

        props = {
            'vms_by_range': vms_by_range,
            'db': db or cls.db,
        }
        return type(name, (cls,), props)

    #
    # Convenience and Helpers
    #
    def get_state_db(self):
        """
        Passthrough helper to the current VM class.
        """
        return self.get_vm().state_db

    def get_block(self):
        """
        Passthrough helper to the current VM class.
        """
        return self.get_vm().block

    def create_transaction(self, *args, **kwargs):
        """
        Passthrough helper to the current VM class.
        """
        return self.get_vm().create_transaction(*args, **kwargs)

    def create_unsigned_transaction(self, *args, **kwargs):
        """
        Passthrough helper to the current VM class.
        """
        return self.get_vm().create_unsigned_transaction(*args, **kwargs)

    def create_header_from_parent(self, parent_header, **header_params):
        """
        Passthrough helper to the current VM class.
        """
        return self.get_vm_class_for_block_number(
            block_number=parent_header.block_number + 1,
        ).create_header_from_parent(parent_header, **header_params)

    #
    # EVM Operations
    #
    @classmethod
    def get_vm_class_for_block_number(cls, block_number):
        """
        Return the vm class for the given block number.
        """
        range = find_range(tuple(cls.vms_by_range.keys()), block_number)
        base_vm_class = cls.vms_by_range[range]
        vm_class = base_vm_class.configure(db=cls.db)
        return vm_class

    def get_vm(self, header=None):
        """
        Return the vm instance for the given block number.
        """
        if header is None:
            header = self.header

        vm_class = self.get_vm_class_for_block_number(header.block_number)
        vm = vm_class(evm=self, header=header)
        return vm

    #
    # Block Retrieval
    #
    def get_block_header_by_hash(self, block_hash):
        validate_word(block_hash)
        block_header = rlp.decode(self.db.get(block_hash), sedes=BlockHeader)
        return block_header

    def get_block_by_number(self, block_number):
        """
        Returns the requested block as specified by block number.
        """
        validate_uint256(block_number)
        block_hash = self._lookup_block_hash(block_number)
        block_header = self.get_block_header_by_hash(block_hash)
        vm = self.get_vm(block_header)
        block = vm.get_block_by_hash(block_hash)
        return block

    def _lookup_block_hash(self, block_number):
        """
        Return the block hash for the given block number.
        """
        validate_uint256(block_number)
        number_to_hash_key = make_block_number_to_hash_lookup_key(block_number)
        # TODO: can raise KeyError
        block_hash = rlp.decode(
            self.db.get(number_to_hash_key),
            sedes=rlp.sedes.binary,
        )
        return block_hash

    def get_block_by_hash(self, block_hash):
        """
        Returns the requested block as specified by block hash.

        TODO: how do we determine the correct EVM class?
        """
        validate_word(block_hash)
        block_header = self.get_block_header_by_hash(block_hash)
        vm = self.get_vm(block_header)
        block = vm.get_block_by_hash(block_hash)
        return block

    #
    # EVM Initialization
    #
    @classmethod
    def from_genesis(cls,
                     genesis_params,
                     genesis_state=None):
        """
        Initialize the EVM from a genesis state.
        """
        if cls.db is None:
            raise ValueError("MetaEVM class must have a db")

        state_db = State(cls.db)

        if genesis_state is None:
            genesis_state = {}

        for account, account_data in genesis_state.items():
            state_db.set_balance(account, account_data['balance'])
            state_db.set_nonce(account, account_data['nonce'])
            state_db.set_code(account, account_data['code'])

            for slot, value in account_data['storage'].items():
                state_db.set_storage(account, slot, value)

        genesis_header = BlockHeader(**genesis_params)
        if genesis_header.state_root != state_db.root_hash:
            raise ValidationError(
                "The provided genesis state root does not match the computed "
                "genesis state root.  Got {0}.  Expected {1}".format(
                    state_db.root_hash,
                    genesis_header.state_root,
                )
            )

        evm = cls(header=genesis_header)
        persist_block_to_db(evm.db, evm.get_block())

        evm.header = evm.create_header_from_parent(genesis_header)
        return evm

    #
    # Mining and Execution API
    #
    def apply_transaction(self, transaction):
        """
        Apply the transaction to the current head block of the EVM.
        """
        vm = self.get_vm()
        computation = vm.apply_transaction(transaction)

        # TODO: icky mutation...
        self.header = vm.block.header
        return computation

    def import_block(self, block):
        """
        Import a complete block.
        """
        if block.number > self.header.block_number:
            raise ValidationError(
                "Attempt to import block #{0}.  Cannot import block with number "
                "greater than current block #{1}.".format(
                    block.number,
                    self.header.block_number,
                )
            )

        # TODO: weird that this vm instance is instantiated with whatever
        # header is currently in place and then that header is immediately
        # discarded.
        vm = self.get_vm()
        imported_block = vm.import_block(block)

        persist_block_to_db(self.db, imported_block)
        self.header = self.get_vm_class_for_block_number(
            block_number=imported_block.number + 1,
        ).create_header_from_parent(imported_block.header)

        return imported_block

    def mine_block(self, **mine_params):
        """
        Mine the current block, applying
        """
        block = self.get_vm().mine_block(**mine_params)
        persist_block_to_db(self.db, block)

        self.header = self.get_vm_class_for_block_number(
            block_number=block.number + 1,
        ).create_header_from_parent(block.header)

        return block

    def configure_header(self, *args, **kwargs):
        vm = self.get_vm()
        self.header = vm.configure_header(*args, **kwargs)
        return self.header
