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
from utils.utils import initialize_logger

if TYPE_CHECKING:
    from evm.storage_emulation import ComputationAPIWithFuzzInfo
    from eth.db.atomic import AtomicDB
    from engine.environment import FuzzingEnvironment
    from engine.components.individual import InputDict
    from eth_typing import HexAddress, HexStr

def to_hex(n: int, length: int) -> str:
    return f'0x{n:0{length}x}'

class TokenBalanceDetector(BaseInvarientDetector):
    erc20_functions: set[str] = {
        'symbol()',
        'decimals()',
        'totalSupply()',
        'balanceOf(address)',
        'transfer(address,uint256)',
        'transferFrom(address,address,uint256)',
        'approve(address,uint256)',
        'allowance(address,address)',
    }

    erc20_events: set[str] = {
        'Transfer(address,address,uint256)',
        'Approval(address,address,uint256)',
    }

    def __init__(self, function_signature_mapping: dict[str, str] = {}, event_signature_mapping: dict[str, str] = {}) -> None:
        self.severity = 'High'
        
        self.signature_mapping: dict[str, str] = event_signature_mapping
        self.storage_snapshot: AtomicDB | None = None

        self.logger = initialize_logger('Detector')

        function_signatures = {signature for hash, signature in function_signature_mapping.items()}
        event_signatures = {signature for hash, signature in event_signature_mapping.items()}
        # only enabled for ERC20 tokens
        self.enabled = function_signatures.issuperset(self.erc20_functions) and event_signatures.issuperset(self.erc20_events)
        if self.enabled:
            self.logger.info('ERC20 token balance invarient detector is enabled')
    
    def prepare_detect_step(self, env: FuzzingEnvironment) -> None:
        if not self.enabled:
            return

        origin_snapshot = env.instrumented_evm.snapshot
        env.instrumented_evm.create_snapshot()
        self.storage_snapshot = env.instrumented_evm.snapshot
        env.instrumented_evm.snapshot = origin_snapshot
    
    def run_detect_step(self, test_input: InputDict, test_output: ComputationAPIWithFuzzInfo, env: FuzzingEnvironment) -> tuple[str, str] | tuple[None, None]:
        if not self.enabled:
            return None, None
        
        assert self.storage_snapshot is not None
        
        contract_address = to_normalized_address(test_input['transaction']['to'])
        transfer_related_addresses: set[HexAddress] = set()

        for log_entry in test_output.get_log_entries():
            event_address = to_normalized_address(log_entry[0])
            if event_address != contract_address:
                continue
            
            topic = to_hex(log_entry[1][0], 64)
            event_signature = self.signature_mapping[topic[:10]]

            if event_signature == 'Transfer(address,address,uint256)':
                from_address = to_normalized_address(to_hex(log_entry[1][1], 40))
                to_address = to_normalized_address(to_hex(log_entry[1][2], 40))
                value = int.from_bytes(log_entry[2], 'big', signed=False)

                # ignore mint or burn
                if from_address != to_normalized_address(ZERO_ADDRESS) and to_address != to_normalized_address(ZERO_ADDRESS):
                    transfer_related_addresses.add(from_address)
                    transfer_related_addresses.add(to_address)
        
        origin_snapshot = env.instrumented_evm.snapshot
        env.instrumented_evm.create_snapshot()
        new_snapshot = env.instrumented_evm.snapshot
        env.instrumented_evm.snapshot = self.storage_snapshot
        env.instrumented_evm.restore_from_snapshot()

        before_balance_sum = self.sum_erc20_token_balance(contract_address, transfer_related_addresses, env)

        env.instrumented_evm.snapshot = new_snapshot
        env.instrumented_evm.restore_from_snapshot()
        env.instrumented_evm.snapshot = origin_snapshot

        after_balance_sum = self.sum_erc20_token_balance(contract_address, transfer_related_addresses, env)

        if before_balance_sum != after_balance_sum:
            return test_input['transaction']['data'][:10], f'Token balance invarient is violated: {before_balance_sum} != {after_balance_sum}'
        
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