#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING, Literal, cast

import os
import sys
import pickle
import logging

from eth import constants
from eth.chains.base import Chain
from eth.chains.mainnet import MAINNET_GENESIS_HEADER
from eth.chains.mainnet.constants import (
    HOMESTEAD_MAINNET_BLOCK,
    TANGERINE_WHISTLE_MAINNET_BLOCK,
    SPURIOUS_DRAGON_MAINNET_BLOCK,
    BYZANTIUM_MAINNET_BLOCK,
    PETERSBURG_MAINNET_BLOCK
)
from eth.constants import ZERO_ADDRESS, CREATE_CONTRACT_ADDRESS
from eth.db.atomic import AtomicDB
from eth.db.backends.memory import MemoryDB
from eth.rlp.accounts import Account
from eth.rlp.headers import BlockHeader
from eth.vm.spoof import SpoofTransaction
from eth.validation import validate_uint256
from eth_utils.hexadecimal import encode_hex, decode_hex
from eth_utils.address import to_canonical_address
from web3 import HTTPProvider
from web3 import Web3

from .storage_emulation import (
    FrontierVMForFuzzTesting,
    HomesteadVMForFuzzTesting,
    TangerineWhistleVMForFuzzTesting,
    SpuriousDragonVMForFuzzTesting,
    ByzantiumVMForFuzzTesting,
    PetersburgVMForFuzzTesting
)

from utils import settings
from utils.utils import initialize_logger
from eth_typing import BlockNumber
from web3.types import BlockData

if TYPE_CHECKING:
    from eth_typing import HexAddress, Address
    from engine.components.individual import InputDict
    from eth.abc import VirtualMachineAPI, SignedTransactionAPI
    from eth.vm.state import BaseState
    from .storage_emulation import EmulatorAccountDB, StateAPIWithFuzzInfo, ComputationAPIWithFuzzInfo

class MyMemoryDB(MemoryDB):
    def __init__(self) -> None:
        self.kv_store = {'storage': dict(), 'account': dict(), 'code': dict()} # type: ignore
    def rst(self) -> None:
        self.kv_store = {'storage': dict(), 'account': dict(), 'code': dict()} # type: ignore

class InstrumentedEVM:
    def __init__(self, eth_node_url: str | None = None) -> None:
        chain_class = Chain.configure(
            __name__='Blockchain',
            vm_configuration=(
                (constants.GENESIS_BLOCK_NUMBER, FrontierVMForFuzzTesting),
                (HOMESTEAD_MAINNET_BLOCK, HomesteadVMForFuzzTesting),
                (TANGERINE_WHISTLE_MAINNET_BLOCK, TangerineWhistleVMForFuzzTesting),
                (SPURIOUS_DRAGON_MAINNET_BLOCK, SpuriousDragonVMForFuzzTesting),
                (BYZANTIUM_MAINNET_BLOCK, ByzantiumVMForFuzzTesting),
                (PETERSBURG_MAINNET_BLOCK, PetersburgVMForFuzzTesting),
            ),
        )
        if eth_node_url and settings.REMOTE_FUZZING:
            self.w3 = Web3(HTTPProvider(eth_node_url))
        else:
            self.w3 = None
        self.chain = chain_class.from_genesis_header(AtomicDB(MyMemoryDB()), MAINNET_GENESIS_HEADER)
        self.logger = initialize_logger('EVM')
        self.accounts: list[HexAddress] = []
        self.snapshot: AtomicDB | None = None
        self.vm: VirtualMachineAPI | None = None

    def get_block_by_blockid(self, block_identifier: int) -> BlockData:
        assert self.w3 is not None
        validate_uint256(block_identifier)
        return self.w3.eth.get_block(block_identifier)

    def get_cached_block_by_id(self, block_number: BlockNumber) -> BlockData:
        block = None
        with open(os.path.dirname(os.path.abspath(__file__))+'/'+'.'.join([str(block_number), 'block']), 'rb') as f:
            block = pickle.load(f)
        return block

    @property
    def storage_emulator(self) -> EmulatorAccountDB:
        assert self.vm is not None
        account_db = cast('BaseState', self.vm.state)._account_db
        return cast('EmulatorAccountDB', account_db)

    def set_vm(self, block_identifier: Literal['latest'] | int = 'latest') -> None:
        block = None
        if self.w3:
            if block_identifier == 'latest':
                block_identifier = self.w3.eth.block_number
            validate_uint256(block_identifier)
            block = self.w3.eth.get_block(block_identifier)
        if not block:
            if block_identifier in [HOMESTEAD_MAINNET_BLOCK, BYZANTIUM_MAINNET_BLOCK,PETERSBURG_MAINNET_BLOCK]:
                block = self.get_cached_block_by_id(block_identifier)
            else:
                self.logger.error('Unknown block identifier.')
                sys.exit(-4)
        block_header = BlockHeader(difficulty=block['difficulty'],
                                   block_number=block['number'],
                                   gas_limit=block['gasLimit'],
                                   timestamp=block['timestamp'],
                                   coinbase=ZERO_ADDRESS,  # default value
                                   parent_hash=block['parentHash'],
                                   uncles_hash=block['uncles'], # type: ignore # TODO: type error
                                   state_root=block['stateRoot'],
                                   transaction_root=block['transactionsRoot'],
                                   receipt_root=block['receiptsRoot'],
                                   bloom=0,  # default value
                                   gas_used=block['gasUsed'],
                                   extra_data=block['extraData'],
                                   mix_hash=block['mixHash'],
                                   nonce=block['nonce'])
        self.vm = self.chain.get_vm(block_header)

    def execute(self, tx: SpoofTransaction, debug: bool = False) -> ComputationAPIWithFuzzInfo:
        assert self.vm is not None
        if debug:
            logging.getLogger('eth.vm.computation.Computation')
            logging.basicConfig(level=logging.DEBUG)
        return cast('ComputationAPIWithFuzzInfo', self.vm.state.apply_transaction(cast('SignedTransactionAPI', tx)))

    def reset(self) -> None:
        cast(MyMemoryDB, self.storage_emulator._raw_store_db.wrapped_db).rst()

    def create_fake_account(self, address: str | bytes, nonce: int = 0, balance: int = settings.ACCOUNT_BALANCE, code: bytes = b'', storage: dict[str, str] | None = None) -> HexAddress:
        assert self.vm is not None
        if storage is None:
            storage = {}
        address = to_canonical_address(address)
        account = Account(nonce=nonce, balance=balance)
        self.storage_emulator._set_account(address, account)
        if code and code != '':
            self.storage_emulator.set_code(address, code)
        if storage:
            for k,v in storage.items():
                self.storage_emulator.set_storage(address, int.from_bytes(decode_hex(k), byteorder='big'), int.from_bytes(decode_hex(v), byteorder='big'))
        self.logger.debug('Created account %s with balance %s', encode_hex(address), account.balance)
        return cast('HexAddress', encode_hex(address))

    def has_account(self, address: str | bytes) -> bool:
        assert self.vm is not None
        address = to_canonical_address(address)
        return self.storage_emulator._has_account(address)

    def deploy_contract(self, creator: str, bin_code: str, amount: int = 0, gas: int = settings.GAS_LIMIT, gas_price: int = settings.GAS_PRICE, debug: bool = False) -> ComputationAPIWithFuzzInfo:
        assert self.vm is not None
        nonce = self.vm.state.get_nonce(to_canonical_address(decode_hex(creator)))
        tx = self.vm.create_unsigned_transaction(
            nonce=nonce,
            gas_price=gas_price,
            gas=gas,
            to=CREATE_CONTRACT_ADDRESS,
            value=amount,
            data=decode_hex(bin_code),
        )
        tx = SpoofTransaction(tx, from_=decode_hex(creator))
        result = self.execute(tx, debug=debug)
        address = to_canonical_address(encode_hex(result.msg.storage_address))
        self.storage_emulator.set_balance(address, 1)
        return result

    def deploy_transaction(self, input: InputDict, gas_price: int = settings.GAS_PRICE, debug: bool = False) -> ComputationAPIWithFuzzInfo:
        assert self.vm is not None
        transaction = input['transaction']
        from_account = to_canonical_address(decode_hex(transaction['from']))
        nonce = self.vm.state.get_nonce(from_account)
        to = to_canonical_address(decode_hex(transaction['to']))
        tx = self.vm.create_unsigned_transaction(
            nonce=nonce,
            gas_price=gas_price,
            gas=transaction['gaslimit'],
            to=to,
            value=transaction['value'],
            data=decode_hex(transaction['data']),
        )
        tx = SpoofTransaction(tx, from_=from_account)

        state = cast('StateAPIWithFuzzInfo', self.vm.state)

        block = input['block']
        if 'timestamp' in block and block['timestamp'] is not None:
            state.fuzzed_timestamp = block['timestamp']
        else:
            state.fuzzed_timestamp = None
        if 'blocknumber' in block and block['blocknumber'] is not None:
            state.fuzzed_blocknumber = block['blocknumber']
        else:
            state.fuzzed_blocknumber = None

        global_state = input['global_state']
        if 'balance' in global_state and global_state['balance'] is not None:
            state.fuzzed_balance = global_state['balance']
        else:
            state.fuzzed_balance = None

        if 'call_return' in global_state and global_state['call_return'] is not None \
                and len(global_state['call_return']) > 0:
            state.fuzzed_call_return = global_state['call_return']
        if 'extcodesize' in global_state and global_state['extcodesize'] is not None \
                and len(global_state['extcodesize']) > 0:
            state.fuzzed_extcodesize = global_state['extcodesize']

        environment = input['environment']
        if 'returndatasize' in environment and environment['returndatasize'] is not None:
            state.fuzzed_returndatasize = environment['returndatasize']

        self.storage_emulator.set_balance(from_account, settings.ACCOUNT_BALANCE)
        return self.execute(tx, debug=debug)

    def get_balance(self, address: Address) -> int:
        return self.storage_emulator.get_balance(address)

    def get_code(self, address: Address) -> bytes:
        return self.storage_emulator.get_code(address)

    def set_code(self, address: Address, code: bytes) -> None:
        self.storage_emulator.set_code(address, code)

    def create_snapshot(self) -> None:
        self.snapshot = self.storage_emulator.record()
        self.storage_emulator.set_snapshot(self.snapshot)

    def restore_from_snapshot(self) -> None:
        assert self.snapshot is not None
        self.storage_emulator.discard(self.snapshot)

    def get_accounts(self) -> list[HexAddress]:
        return [cast('HexAddress', encode_hex(x)) for x in self.storage_emulator._account_emulator.keys()]

    def set_vm_by_name(self, evm_version: str) -> None:
        if   evm_version == 'homestead':
            self.set_vm(HOMESTEAD_MAINNET_BLOCK)
        elif evm_version == 'byzantium':
            self.set_vm(BYZANTIUM_MAINNET_BLOCK)
        elif evm_version == 'petersburg':
            self.set_vm(PETERSBURG_MAINNET_BLOCK)
        else:
            raise Exception('Unknown EVM version, please choose either \'homestead\', \'byzantium\' or \'petersburg\'.')

    def create_fake_accounts(self) -> None:
        self.accounts.append(self.create_fake_account('0xcafebabecafebabecafebabecafebabecafebabe'))
        for address in settings.ATTACKER_ACCOUNTS:
            self.accounts.append(self.create_fake_account(address))
