#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING, TypedDict, cast

import random
import copy

from eth._utils.address import force_bytes_to_address
from eth_hash.auto import keccak
from eth_utils.conversions import to_bytes, to_hex
from eth_utils.address import to_normalized_address
from eth.chains.mainnet import MainnetHomesteadVM
from eth.constants import BLANK_ROOT_HASH, EMPTY_SHA3
from eth.abc import AccountDatabaseAPI, StateAPI, ComputationAPI
from eth.rlp.accounts import Account
from eth.tools._utils.normalization import to_int
from eth.validation import validate_uint256, validate_canonical_address, validate_is_bytes
from eth.vm.forks.frontier import FrontierVM
from eth.vm.forks.frontier.state import FrontierState
from eth.vm.forks.frontier.computation import FrontierComputation
from eth.vm.forks.homestead.state import HomesteadState
from eth.vm.forks.homestead.computation import HomesteadComputation
from eth.vm.forks.tangerine_whistle import TangerineWhistleVM
from eth.vm.forks.tangerine_whistle.state import TangerineWhistleState
from eth.vm.forks.tangerine_whistle.computation import TangerineWhistleComputation
from eth.vm.forks.spurious_dragon import SpuriousDragonVM
from eth.vm.forks.spurious_dragon.state import SpuriousDragonState
from eth.vm.forks.spurious_dragon.computation import SpuriousDragonComputation
from eth.vm.forks.byzantium import ByzantiumVM
from eth.vm.forks.byzantium.state import ByzantiumState
from eth.vm.forks.byzantium.computation import ByzantiumComputation
from eth.vm.forks.petersburg import PetersburgVM
from eth.vm.forks.petersburg.state import PetersburgState
from eth.vm.forks.petersburg.computation import PetersburgComputation

from web3 import HTTPProvider
from web3 import Web3

from utils import settings

if TYPE_CHECKING:
    from eth_typing import Address, HexAddress, Hash32, BlockNumber
    from eth.abc import MessageAPI, TransactionContextAPI, OpcodeAPI
    from eth.db.atomic import AtomicDB
    from eth.exceptions import VMError
    from eth.vm.stack import Stack
    from collections import deque

# STORAGE EMULATOR
class EmulatorAccountDB(AccountDatabaseAPI):
    _raw_store_db: AtomicDB # db is an `AtomicDB` whose wrapped_db is `MyMemoryDB`, see evm/__init__.py

    def __init__(self, db: AtomicDB, state_root: Hash32 = BLANK_ROOT_HASH) -> None:
        if settings.REMOTE_FUZZING and settings.RPC_URL:
            self._w3 = Web3(HTTPProvider(settings.RPC_URL))
            self._remote = self._w3.eth
        else:
            self._remote = None
        self._state_root = BLANK_ROOT_HASH
        self._raw_store_db = db
        self._snapshot: AtomicDB | None = None

    def set_snapshot(self, snapshot: AtomicDB) -> None:
        self._snapshot = snapshot

    @property
    def state_root(self) -> Hash32:
        return self._state_root

    @state_root.setter
    def state_root(self, value: Hash32) -> None:
        self._state_root = value
    
    def has_root(self, state_root: bytes) -> bool:
        return self.state_root != BLANK_ROOT_HASH

    @property
    def _storage_emulator(self) -> dict[Address, dict[int, int]]:
        # see `MyMemoryDB` in evm/__init__.py
        return self._raw_store_db['storage'] # type: ignore

    @property
    def _account_emulator(self) -> dict[Address, Account]:
        # see `MyMemoryDB` in evm/__init__.py
        return self._raw_store_db['account'] # type: ignore

    @property
    def _code_storage_emulator(self) -> dict[bytes, bytes]:
        # see `MyMemoryDB` in evm/__init__.py
        return self._raw_store_db['code'] # type: ignore

    def get_storage(self, address: Address, slot: int, from_journal: bool = True) -> int:
        validate_canonical_address(address, title='Storage Address')
        validate_uint256(slot, title='Storage Slot')
        if address in self._storage_emulator and slot in self._storage_emulator[address] or not self._remote:
            try:
                return self._storage_emulator[address][slot]
            except KeyError:
                return 0
        else:
            result = self._remote.get_storage_at(address, slot, settings.BLOCK_HEIGHT)
            result = to_int(result.hex())
            self.set_storage(address, slot, result)
            if self._snapshot is not None:
                snapshot_storage_emulator = cast(dict['Address', dict[int, int]], self._snapshot['storage']) # type: ignore
                if address not in snapshot_storage_emulator:
                    snapshot_storage_emulator[address] = dict()
                snapshot_storage_emulator[address][slot] = result
            return result

    def set_storage(self, address: Address, slot: int, value: int) -> None:
        validate_uint256(value, title='Storage Value')
        validate_uint256(slot, title='Storage Slot')
        validate_canonical_address(address, title='Storage Address')
        if address not in self._storage_emulator:
            self._storage_emulator[address] = dict()
        self._storage_emulator[address][slot] = value

    def delete_storage(self, address: Address) -> None:
        validate_canonical_address(address, title='Storage Address')
        if address in self._storage_emulator:
            del self._storage_emulator[address]
    
    def is_storage_warm(self, address: Address, slot: int) -> bool:
        # TODO: may lead to higher gas consumption
        return False

    def mark_storage_warm(self, address: Address, slot: int) -> None:
        pass

    def _get_account(self, address: Address) -> Account:
        if address in self._account_emulator:
            account = self._account_emulator[address]
        elif not self._remote:
            account = Account()
        else:
            code = self._remote.get_code(address, settings.BLOCK_HEIGHT)
            if code:
                code_hash = keccak(code)
                self._code_storage_emulator[code_hash] = code
                if self._snapshot is not None:
                    snapshot_code_storage_emulator = cast(dict[bytes, bytes], self._snapshot['code']) # type: ignore
                    snapshot_code_storage_emulator[code_hash] = code
            else:
                code_hash = EMPTY_SHA3
            account = Account(
                int(self._remote.get_transaction_count(address, settings.BLOCK_HEIGHT)) + 1,
                self._remote.get_balance(address, settings.BLOCK_HEIGHT),
                BLANK_ROOT_HASH,
                code_hash
            )
            if self._snapshot is not None:
                snapshot_account_emulator = cast(dict['Address', Account], self._snapshot['account']) # type: ignore
                snapshot_account_emulator[address] = account
            self._set_account(address, account)
        return account

    def _has_account(self, address: Address) -> bool:
        return address in self._account_emulator

    def _set_account(self, address: Address, account: Account) -> None:
        self._account_emulator[address] = account
    
    def get_balance(self, address: Address) -> int:
        validate_canonical_address(address, title='Storage Address')
        return self._get_account(address).balance

    def set_balance(self, address: Address, balance: int) -> None:
        validate_canonical_address(address, title='Storage Address')
        validate_uint256(balance, title='Account Balance')
        account = self._get_account(address)
        self._set_account(address, account.copy(balance=balance))

    def get_nonce(self, address: Address) -> int:
        validate_canonical_address(address, title='Storage Address')
        a = self._get_account(address)
        return a.nonce

    def set_nonce(self, address: Address, nonce: int) -> None:
        validate_canonical_address(address, title='Storage Address')
        validate_uint256(nonce, title='Nonce')
        account = self._get_account(address)
        self._set_account(address, account.copy(nonce=nonce))

    def increment_nonce(self, address: Address) -> None:
        current_nonce = self.get_nonce(address)
        self.set_nonce(address, current_nonce + 1)

    def set_code(self, address: Address, code: bytes) -> None:
        validate_canonical_address(address, title='Storage Address')
        validate_is_bytes(code, title='Code')
        account = self._get_account(address)
        code_hash = keccak(code)
        self._code_storage_emulator[code_hash] = code
        self._set_account(address, account.copy(code_hash=code_hash))

    def get_code(self, address: Address) -> bytes:
        validate_canonical_address(address, title='Storage Address')
        code_hash = self.get_code_hash(address)
        if code_hash == EMPTY_SHA3:
            return b''
        assert code_hash in self._code_storage_emulator
        return self._code_storage_emulator[code_hash]

    def get_code_hash(self, address: Address) -> Hash32:
        validate_canonical_address(address, title='Storage Address')
        account = self._get_account(address)
        return account.code_hash

    def delete_code(self, address: Address) -> None:
        validate_canonical_address(address, title='Storage Address')
        account = self._get_account(address)
        code_hash = account.code_hash
        self._set_account(address, account.copy(code_hash=EMPTY_SHA3))
        if code_hash in self._code_storage_emulator:
            del self._code_storage_emulator[code_hash]
    
    def account_has_code_or_nonce(self, address: Address) -> bool:
        return self.get_nonce(address) != 0 or self.get_code_hash(address) != EMPTY_SHA3
    
    def delete_account(self, address: Address) -> None:
        validate_canonical_address(address, title='Storage Address')
        self.delete_code(address)
        if address in self._storage_emulator:
            del self._storage_emulator[address]
        if address in self._account_emulator:
            del self._account_emulator[address]
    
    def account_exists(self, address: Address) -> bool:
        validate_canonical_address(address, title='Storage Address')
        return address in self._account_emulator

    def touch_account(self, address: Address) -> None:
        validate_canonical_address(address, title='Storage Address')
        account = self._get_account(address)
        self._set_account(address, account)

    def account_is_empty(self, address: Address) -> bool:
        return not self.account_has_code_or_nonce(address) and self.get_balance(address) == 0

    def is_address_warm(self, address: Address) -> bool:
        # TODO: may lead to higher gas consumption
        return False
    
    def mark_address_warm(self, address: Address) -> None:
        pass

    def record(self) -> AtomicDB:
        checkpoint = copy.deepcopy(self._raw_store_db)
        return checkpoint

    def discard(self, checkpoint: AtomicDB) -> None:
        self._raw_store_db = copy.deepcopy(checkpoint)

    def commit(self, checkpoint: AtomicDB) -> None:
        pass

    def lock_changes(self) -> None:
        pass
    
    def make_state_root(self) -> Hash32:
        return BLANK_ROOT_HASH

    def persist(self) -> None:
        pass

class StateAPIWithFuzzInfo(StateAPI):
    '''
    This class is only used for unsafe type cast from StateAPI, and would not be instantiated.
    All the following attributes should be checked of existence before accessing.
    '''
    # environmental instrumentation values
    fuzzed_timestamp: int | None
    fuzzed_blocknumber: int | None
    fuzzed_balance: int | None
    fuzzed_call_return: dict[HexAddress, int] | None
    fuzzed_extcodesize: dict[HexAddress, int | None] | None
    fuzzed_returndatasize: dict[HexAddress, int | None] | None

    # reentrancy helper
    reentrancy_helper: HexAddress | None
    reentrancy_tx_data: bytes | None

    # gasless send detector flags
    zero_call_gas: bool | None
    full_call_gas: bool | None

    # reentrancy detector flags
    forbid_internal_transactions: bool | None
    internal_return_values: deque[tuple[bytes, int, int]] | None

    # timestamp dependency detector flags
    random_timestamp: bool | None

TracedInstruction = TypedDict('TracedInstruction', {
    'pc': int,
    'op': str,
    'depth': int,
    'error': 'VMError',
    'stack': list[tuple[type, int | bytes]],
    'memory': bytes | None,
    'gas': int,
    'gas_used_by_opcode': int
})

class ComputationAPIWithFuzzInfo(ComputationAPI):
    '''
    This class is only used for unsafe type cast from ComputationAPI, and would not be instantiated.
    '''
    trace: list[TracedInstruction]
    children: list[ComputationAPIWithFuzzInfo]

def get_block_hash_for_testing(self: StateAPI, block_number: BlockNumber) -> bytes:
    if block_number >= self.block_number:
        return b''
    elif block_number < self.block_number - 256:
        return b''
    else:
        return keccak(to_bytes(text='{0}'.format(block_number)))

def fuzz_timestamp_opcode_fn(computation: ComputationAPI) -> None:
    state = cast(StateAPIWithFuzzInfo, computation.state)
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state, 'fuzzed_timestamp') and state.fuzzed_timestamp is not None:
        computation.stack_push_int(state.fuzzed_timestamp)
    else:
        computation.stack_push_int(computation.state.timestamp)

def fuzz_blocknumber_opcode_fn(computation: ComputationAPI) -> None:
    state = cast(StateAPIWithFuzzInfo, computation.state)
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state, 'fuzzed_blocknumber') and state.fuzzed_blocknumber is not None:
        computation.stack_push_int(state.fuzzed_blocknumber)
    elif hasattr(computation.state, 'random_timestamp') and state.random_timestamp == True:
        computation.stack_push_int(random.randint(0, 1800000000))
    else:
        computation.stack_push_int(computation.state.block_number)

def fuzz_call_opcode_fn(computation: ComputationAPI, opcode_fn: OpcodeAPI) -> HexAddress:
    gas = computation.stack_pop1_int()
    to = computation.stack_pop1_bytes()
    _to = to_normalized_address(to_hex(force_bytes_to_address(to)))
    state = cast(StateAPIWithFuzzInfo, computation.state)
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state, 'fuzzed_call_return') and state.fuzzed_call_return is not None\
            and _to in state.fuzzed_call_return and state.fuzzed_call_return[_to] is not None:
        (
            value,
            memory_input_start_position,
            memory_input_size,
            memory_output_start_position,
            memory_output_size,
        ) = computation.stack_pop_ints(5)
        computation.memory_write(memory_output_start_position, memory_output_size, b'\x00' * memory_output_size if random.randint(1, 2) == 1 else b'\xff' * memory_output_size)
        computation.stack_push_int(state.fuzzed_call_return[_to])
    elif hasattr(computation.state, 'forbid_internal_transactions') and hasattr(computation.state, 'internal_return_values')\
            and state.forbid_internal_transactions == True and state.internal_return_values is not None:
        (
            value,
            memory_input_start_position,
            memory_input_size,
            memory_output_start_position,
            memory_output_size,
        ) = computation.stack_pop_ints(5)
        if len(state.internal_return_values) > 0:
            return_data, success, gas_consumed = state.internal_return_values.popleft()
        else:
            # TODO: why would this condition happen?
            return_data, success, gas_consumed = b'', 1, 0
        computation.memory_write(memory_output_start_position, memory_output_size, return_data)
        computation.stack_push_int(success)
        computation.consume_gas(gas_consumed, 'emulating internal call')
    else:
        if hasattr(computation.state, 'reentrancy_helper') and hasattr(computation.state, 'reentrancy_tx_data')\
                and state.reentrancy_helper is not None and _to == state.reentrancy_helper and state.reentrancy_tx_data is not None:
            tx_data_size = len(state.reentrancy_tx_data)
            # reassign memory space for tx_data
            free_space_pointer = int.from_bytes(computation.memory_read_bytes(0x40, 32), 'big', signed=False)
            computation.memory_write(0x40, 32, (free_space_pointer + tx_data_size).to_bytes(32, 'big'))
            computation.extend_memory(free_space_pointer, tx_data_size)
            # write tx_data to memory
            computation.memory_write(free_space_pointer, tx_data_size, state.reentrancy_tx_data)
            # substitute input data with tx_data
            (
                value,
                memory_input_start_position,
                memory_input_size,
            ) = computation.stack_pop_ints(3)
            computation.stack_push_int(tx_data_size)
            computation.stack_push_int(free_space_pointer)
            computation.stack_push_int(value)
            # stop next reentrancy
            state.reentrancy_tx_data = b''
        computation.stack_push_bytes(to)
        if hasattr(computation.state, 'zero_call_gas') and state.zero_call_gas == True:
            computation.stack_push_int(0)
        elif hasattr(computation.state, 'full_call_gas') and state.full_call_gas == True:
            computation.stack_push_int(computation.get_gas_remaining())
        else:
            computation.stack_push_int(gas)
        opcode_fn(computation=computation)
    return _to

def fuzz_staticcall_opcode_fn(computation: ComputationAPI, opcode_fn: OpcodeAPI) -> HexAddress:
    gas = computation.stack_pop1_int()
    to = computation.stack_pop1_bytes()
    _to = to_normalized_address(to_hex(force_bytes_to_address(to)))
    state = cast(StateAPIWithFuzzInfo, computation.state)
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state, 'fuzzed_call_return') and state.fuzzed_call_return is not None\
            and _to in state.fuzzed_call_return and state.fuzzed_call_return[_to] is not None:
        (
            memory_input_start_position,
            memory_input_size,
            memory_output_start_position,
            memory_output_size,
        ) = computation.stack_pop_ints(4)
        computation.memory_write(memory_output_start_position, memory_output_size, b'\x00' * memory_output_size if random.randint(1, 2) == 1 else b'\xff' * memory_output_size)
        computation.stack_push_int(state.fuzzed_call_return[_to])
    else:
        computation.stack_push_bytes(to)
        computation.stack_push_int(gas)
        opcode_fn(computation=computation)
    return _to

def fuzz_extcodesize_opcode_fn(computation: ComputationAPI, opcode_fn: OpcodeAPI) -> None:
    to = computation.stack_pop1_bytes()
    _to = to_normalized_address(to_hex(force_bytes_to_address(to)))
    state = cast(StateAPIWithFuzzInfo, computation.state)
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state, 'fuzzed_extcodesize') and state.fuzzed_extcodesize is not None\
            and _to in state.fuzzed_extcodesize and state.fuzzed_extcodesize[_to] is not None:
        computation.stack_push_int(cast(int, state.fuzzed_extcodesize[_to]))
    else:
        computation.stack_push_bytes(to)
        opcode_fn(computation=computation)

def fuzz_returndatasize_opcode_fn(previous_call_address: HexAddress | None, computation: ComputationAPI, opcode_fn: OpcodeAPI) -> None:
    opcode_fn(computation=computation)
    size = computation.stack_pop1_int()
    state = cast(StateAPIWithFuzzInfo, computation.state)
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state, 'fuzzed_returndatasize') and state.fuzzed_returndatasize is not None\
            and previous_call_address in state.fuzzed_returndatasize and state.fuzzed_returndatasize[previous_call_address] is not None:
        computation.stack_push_int(cast(int, state.fuzzed_returndatasize[previous_call_address]))
    else:
        computation.stack_push_int(size)

def fuzz_balance_opcode_fn(computation: ComputationAPI, opcode_fn: OpcodeAPI) -> None:
    state = cast(StateAPIWithFuzzInfo, computation.state)
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state, 'fuzzed_balance') and state.fuzzed_balance is not None:
        computation.stack_pop1_bytes()
        computation.stack_push_int(state.fuzzed_balance)
    else:
        opcode_fn(computation=computation)

@classmethod
def fuzz_apply_computation(cls: type[ComputationAPI], state: StateAPI, message: MessageAPI, transaction_context: TransactionContextAPI) -> ComputationAPI:
    with cls(state, message, transaction_context) as computation:
        _compuation = cast(ComputationAPIWithFuzzInfo, computation)
        _compuation.trace = []

        # Early exit on pre-compiles
        from eth.vm.computation import NO_RESULT
        precompile = computation.precompiles.get(message.code_address, NO_RESULT)
        if precompile is not NO_RESULT:
            precompile(computation)
            return computation

        opcode_lookup = computation.opcodes
        previous_stack = []
        previous_call_address = None
        memory = None

        for opcode in computation.code:
            try:
                opcode_fn = opcode_lookup[opcode]
            except KeyError:
                from eth.vm.logic.invalid import InvalidOpcode
                opcode_fn = InvalidOpcode(opcode)

            from eth.exceptions import Halt
            from copy import deepcopy

            previous_pc = computation.code.program_counter
            previous_gas = computation.get_gas_remaining()

            try:
                if   opcode == 0x42:  # TIMESTAMP
                    fuzz_timestamp_opcode_fn(computation=computation)
                elif opcode == 0x43:  # NUMBER
                    fuzz_blocknumber_opcode_fn(computation=computation)
                elif opcode == 0x31:  # BALANCE
                    fuzz_balance_opcode_fn(computation=computation, opcode_fn=opcode_fn)
                elif opcode == 0xf1: # CALL
                    previous_call_address = fuzz_call_opcode_fn(computation=computation, opcode_fn=opcode_fn)
                elif opcode == 0xfa: # STATICCALL
                    previous_call_address = fuzz_staticcall_opcode_fn(computation=computation, opcode_fn=opcode_fn)
                elif opcode == 0x3b: # EXTCODESIZE
                    fuzz_extcodesize_opcode_fn(computation=computation, opcode_fn=opcode_fn)
                elif opcode == 0x3d: # RETURNDATASIZE
                    fuzz_returndatasize_opcode_fn(previous_call_address, computation=computation, opcode_fn=opcode_fn)
                elif opcode == 0x20: # SHA3
                    start_position, size = computation.stack_pop_ints(2)
                    memory = computation.memory_read_bytes(start_position, size)
                    computation.stack_push_int(size)
                    computation.stack_push_int(start_position)
                    opcode_fn(computation=computation)
                else:
                    opcode_fn(computation=computation)
            except Halt:
                break
            finally:
                _compuation.trace.append({
                    'pc': max(0, previous_pc - 1),
                    'op': opcode_fn.mnemonic,
                    'depth': computation.msg.depth + 1,
                    'error': deepcopy(computation._error),
                    'stack': previous_stack,
                    'memory': memory,
                    'gas': computation.get_gas_remaining(),
                    'gas_used_by_opcode' : previous_gas - computation.get_gas_remaining()
                })
                previous_stack = copy.deepcopy(cast('Stack', computation._stack).values)
    return computation

# VMs

# FRONTIER
FrontierComputationForFuzzTesting = FrontierComputation.configure(
    __name__='FrontierComputationForFuzzTesting',
    apply_computation=fuzz_apply_computation,
)
FrontierStateForFuzzTesting = FrontierState.configure(
    __name__='FrontierStateForFuzzTesting',
    get_ancestor_hash=get_block_hash_for_testing,
    computation_class=FrontierComputationForFuzzTesting,
    account_db_class=EmulatorAccountDB,
)
FrontierVMForFuzzTesting = FrontierVM.configure(
    __name__='FrontierVMForFuzzTesting',
    _state_class=FrontierStateForFuzzTesting,
)

# HOMESTEAD
HomesteadComputationForFuzzTesting = HomesteadComputation.configure(
    __name__='HomesteadComputationForFuzzTesting',
    apply_computation=fuzz_apply_computation,
)
HomesteadStateForFuzzTesting = HomesteadState.configure(
    __name__='HomesteadStateForFuzzTesting',
    get_ancestor_hash=get_block_hash_for_testing,
    computation_class=HomesteadComputationForFuzzTesting,
    account_db_class=EmulatorAccountDB,
)
HomesteadVMForFuzzTesting = MainnetHomesteadVM.configure(
    __name__='HomesteadVMForFuzzTesting',
    _state_class=HomesteadStateForFuzzTesting,
)

# TANGERINE WHISTLE
TangerineWhistleComputationForFuzzTesting = TangerineWhistleComputation.configure(
    __name__='TangerineWhistleComputationForFuzzTesting',
    apply_computation=fuzz_apply_computation,
)
TangerineWhistleStateForFuzzTesting = TangerineWhistleState.configure(
    __name__='TangerineWhistleStateForFuzzTesting',
    get_ancestor_hash=get_block_hash_for_testing,
    computation_class=TangerineWhistleComputationForFuzzTesting,
    account_db_class=EmulatorAccountDB,
)
TangerineWhistleVMForFuzzTesting = TangerineWhistleVM.configure(
    __name__='TangerineWhistleVMForFuzzTesting',
    _state_class=TangerineWhistleStateForFuzzTesting,
)

# SPURIOUS DRAGON
SpuriousDragonComputationForFuzzTesting = SpuriousDragonComputation.configure(
    __name__='SpuriousDragonComputationForFuzzTesting',
    apply_computation=fuzz_apply_computation,
)
SpuriousDragonStateForFuzzTesting = SpuriousDragonState.configure(
    __name__='SpuriousDragonStateForFuzzTesting',
    get_ancestor_hash=get_block_hash_for_testing,
    computation_class=SpuriousDragonComputationForFuzzTesting,
    account_db_class=EmulatorAccountDB,
)
SpuriousDragonVMForFuzzTesting = SpuriousDragonVM.configure(
    __name__='SpuriousDragonVMForFuzzTesting',
    _state_class=SpuriousDragonStateForFuzzTesting,
)

# BYZANTIUM
ByzantiumComputationForFuzzTesting = ByzantiumComputation.configure(
    __name__='ByzantiumComputationForFuzzTesting',
    apply_computation=fuzz_apply_computation,
)
ByzantiumStateForFuzzTesting = ByzantiumState.configure(
    __name__='ByzantiumStateForFuzzTesting',
    get_ancestor_hash=get_block_hash_for_testing,
    computation_class=ByzantiumComputationForFuzzTesting,
    account_db_class=EmulatorAccountDB,
)
ByzantiumVMForFuzzTesting = ByzantiumVM.configure(
    __name__='ByzantiumVMForFuzzTesting',
    _state_class=ByzantiumStateForFuzzTesting,
)

# PETERSBURG
PetersburgComputationForFuzzTesting = PetersburgComputation.configure(
    __name__='PetersburgComputationForFuzzTesting',
    apply_computation=fuzz_apply_computation,
)
PetersburgStateForFuzzTesting = PetersburgState.configure(
    __name__='PetersburgStateForFuzzTesting',
    get_ancestor_hash=get_block_hash_for_testing,
    computation_class=PetersburgComputationForFuzzTesting,
    account_db_class=EmulatorAccountDB,
)
PetersburgVMForFuzzTesting = PetersburgVM.configure(
    __name__='PetersburgVMForFuzzTesting',
    _state_class=PetersburgStateForFuzzTesting,
)
