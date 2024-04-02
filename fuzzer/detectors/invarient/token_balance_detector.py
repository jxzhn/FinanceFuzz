#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
from typing import TYPE_CHECKING, cast

from .base import BaseInvarientDetector
from web3 import Web3
from eth.constants import ZERO_ADDRESS
from eth_utils.address import to_normalized_address
from eth_abi.abi import encode
from utils import settings
from utils.utils import to_hex

if TYPE_CHECKING:
    from evm.storage_emulation import ComputationAPIWithFuzzInfo
    from eth.db.atomic import AtomicDB
    from engine.environment import FuzzingEnvironment
    from engine.components.individual import InputDict
    from eth_typing import HexAddress, HexStr

class TokenBalanceDetector(BaseInvarientDetector):
    def __init__(self, is_erc20: bool) -> None:
        self.severity = 'High'

        self.is_erc20 = is_erc20
        self.storage_snapshot: AtomicDB | None = None
    
    def reset(self) -> None:
        self.storage_snapshot = None

    @staticmethod
    def create_storage_snapshot(env: FuzzingEnvironment) -> AtomicDB:
        origin_snapshot = env.instrumented_evm.snapshot

        env.instrumented_evm.create_snapshot()
        storage_snapshot = env.instrumented_evm.snapshot

        env.instrumented_evm.snapshot = origin_snapshot

        assert storage_snapshot is not None
        return storage_snapshot

    @staticmethod
    def restore_storage_snapshot(snapshot: AtomicDB, env: FuzzingEnvironment) -> None:
        origin_snapshot = env.instrumented_evm.snapshot

        env.instrumented_evm.snapshot = snapshot
        env.instrumented_evm.restore_from_snapshot()

        env.instrumented_evm.snapshot = origin_snapshot
    
    def prepare_detect_step(self, env: FuzzingEnvironment) -> None:
        if not self.is_erc20:
            return

        self.storage_snapshot = TokenBalanceDetector.create_storage_snapshot(env)
    
    def run_detect_step(self, tx_input: InputDict, tx_output: ComputationAPIWithFuzzInfo, env: FuzzingEnvironment) -> tuple[str, str] | tuple[None, None]:
        if not self.is_erc20:
            return None, None
        
        assert self.storage_snapshot is not None
        
        contract_address = to_normalized_address(tx_input['transaction']['to'])
        transfer_related_addresses: set[HexAddress] = set()

        for log_entry in tx_output.get_log_entries():
            event_address = to_normalized_address(log_entry[0])
            if event_address != contract_address:
                continue
            
            topic = to_hex(log_entry[1][0], 64)

            if topic[:10] == Web3.keccak(text='Transfer(address,address,uint256)').hex()[:10]:
                from_address = to_normalized_address(to_hex(log_entry[1][1], 40))
                to_address = to_normalized_address(to_hex(log_entry[1][2], 40))
                value = int.from_bytes(log_entry[2], 'big', signed=False)

                # ignore mint or burn
                if from_address != to_normalized_address(ZERO_ADDRESS) and to_address != to_normalized_address(ZERO_ADDRESS):
                    transfer_related_addresses.add(from_address)
                    transfer_related_addresses.add(to_address)
        
        current_snapshot = TokenBalanceDetector.create_storage_snapshot(env)

        after_balance_sum = self.sum_erc20_token_balance(contract_address, transfer_related_addresses, env)

        TokenBalanceDetector.restore_storage_snapshot(self.storage_snapshot, env)
        before_balance_sum = self.sum_erc20_token_balance(contract_address, transfer_related_addresses, env)
        
        TokenBalanceDetector.restore_storage_snapshot(current_snapshot, env)

        if before_balance_sum != after_balance_sum:
            return tx_input['transaction']['data'][:10], f'Token balance invarient is violated: {before_balance_sum} != {after_balance_sum}'
        
        return None, None
    
    @staticmethod
    def sum_erc20_token_balance(contract_address: HexAddress, addresses: set[HexAddress], env: FuzzingEnvironment) -> int:
        balance_sum = 0
        
        for address in addresses:
            balance_query_result = env.instrumented_evm.deploy_transaction({
                'transaction': {
                    'from': to_normalized_address(ZERO_ADDRESS),
                    'to': contract_address,
                    'value': 0,
                    'data': cast('HexStr', Web3.keccak(text='balanceOf(address)').hex()[:10] + encode(['address'], [address]).hex()),
                    'gaslimit': settings.GAS_LIMIT,
                },
                'block': {},
                'environment': {},
                'global_state': {},
            })
            balance = int.from_bytes(balance_query_result.output, 'big', signed=False) # uint256
            balance_sum += balance
        
        return balance_sum