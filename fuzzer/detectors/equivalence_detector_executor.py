#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING, cast

import time
from collections import deque

from utils.utils import print_individual_solution_as_transaction, initialize_logger, to_hex
from eth_utils.address import to_normalized_address, to_canonical_address
from web3 import Web3
from eth.constants import ZERO_ADDRESS
from .equivalence.gasless_send_detector import GaslessSendDetector
from .equivalence.reentrancy_detector import ReentrancyDetector
from eth_abi.abi import encode
from utils import settings
   
if TYPE_CHECKING:
    from eth.db.atomic import AtomicDB
    from engine.components.individual import Individual, InputDict
    from engine.environment import FuzzingEnvironment, ErrorRecord
    from .equivalence.base import BaseEquivalenceDetector
    from evm.storage_emulation import ComputationAPIWithFuzzInfo
    from eth_typing import HexAddress, HexStr

class EquivalenceDetectorExecutor:
    def __init__(self, contract_types: list[str], function_signature_mapping: dict[str, str] = {}) -> None:
        self.function_signature_mapping = function_signature_mapping
        self.logger = initialize_logger('Detector')
        self.is_erc20 = 'ERC20' in contract_types

        self.initial_snapshot: AtomicDB | None = None
        self.transaction_inputs: list[InputDict] = []
        self.transaction_outputs: list[ComputationAPIWithFuzzInfo] = []

        self.detectors: list[BaseEquivalenceDetector] = [GaslessSendDetector(), ReentrancyDetector()]

    def reset_detectors(self) -> None:
        self.initial_snapshot = None
        self.transaction_inputs = []
        self.transaction_outputs = []

    @staticmethod
    def error_exists(errors: list[ErrorRecord], type: str) -> bool:
        for error in errors:
            if error['type'] == type:
                return True
        return False

    @staticmethod
    def add_error(errors: dict[str, list[ErrorRecord]], target: str, type: str, individual: Individual, env: FuzzingEnvironment, detector: BaseEquivalenceDetector) -> bool:
        assert env.execution_begin is not None
        error: ErrorRecord = {
            'swc_id': -1,
            'severity': detector.severity,
            'type': type,
            'individual': individual.solution,
            'time': time.time() - env.execution_begin,
        }
        if not target in errors:
            errors[target] = [error]
            return True
        elif not EquivalenceDetectorExecutor.error_exists(errors[target], type):
            errors[target].append(error)
            return True
        return False

    @staticmethod
    def get_color_for_severity(severity: str) -> str:
        if severity == 'High':
            return '\u001b[31m' # Red
        if severity == 'Medium':
            return '\u001b[33m' # Yellow
        if severity == 'Low':
            return '\u001b[32m' # Green
        return ''

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
    
    def prepare_detectors(self, env: FuzzingEnvironment) -> None:
        self.reset_detectors()
        self.initial_snapshot = EquivalenceDetectorExecutor.create_storage_snapshot(env)
    
    def add_transaction_step(self, tx_input: InputDict, tx_output: ComputationAPIWithFuzzInfo) -> None:
        self.transaction_inputs.append(tx_input)
        self.transaction_outputs.append(tx_output)

    def run_detectors(self, errors: dict[str, list[ErrorRecord]], individual: Individual, env: FuzzingEnvironment) -> None:
        assert self.initial_snapshot is not None
        final_snapshot = EquivalenceDetectorExecutor.create_storage_snapshot(env)

        ether_related_addresses: set[HexAddress] = set()
        erc20_related_addresses: set[HexAddress] = set()

        # collect related addresses
        for transaction_index in range(len(self.transaction_inputs)):
            tx_input = self.transaction_inputs[transaction_index]
            tx_output = self.transaction_outputs[transaction_index]

            contract_address = to_normalized_address(tx_input['transaction']['to'])

            ether_related_addresses |= EquivalenceDetectorExecutor.get_addresses_in_transaction(tx_output)
            if self.is_erc20:
                erc20_related_addresses |= EquivalenceDetectorExecutor.get_erc20_transfer_related_addresses(contract_address, tx_output)
        
        # get origin balances after transactions
        ether_map = {address: EquivalenceDetectorExecutor.get_address_balance(address, env) for address in ether_related_addresses}
        erc20_token_map = {address: EquivalenceDetectorExecutor.get_erc20_token_balance(contract_address, address, env) for address in erc20_related_addresses}
        
        for detector in self.detectors:
            if not detector.is_enable:
                continue

            EquivalenceDetectorExecutor.restore_storage_snapshot(self.initial_snapshot, env)
            
            # run detector-flavored transactions
            for transaction_index in range(len(self.transaction_inputs)):
                tx_input = self.transaction_inputs[transaction_index]
                tx_output = self.transaction_outputs[transaction_index]
                detector.run_flavored_transaction(tx_input, tx_output, transaction_index, env)
            detector.final(env)
            
            # check if equivalence is violated
            changed_ether_map = {address: EquivalenceDetectorExecutor.get_address_balance(address, env) for address in ether_related_addresses}
            changed_erc20_token_map = {address: EquivalenceDetectorExecutor.get_erc20_token_balance(contract_address, address, env) for address in erc20_related_addresses}

            if ether_map != changed_ether_map or erc20_token_map != changed_erc20_token_map:
                EquivalenceDetectorExecutor.add_error(errors, individual.hash, detector.error_msg, individual, env, detector)
                color = EquivalenceDetectorExecutor.get_color_for_severity(detector.severity)
                self.logger.title(color+'-----------------------------------------------------')
                self.logger.title(color+'        !!! Equivalence violated detected !!!        ')
                self.logger.title(color+'-----------------------------------------------------')
                self.logger.title(color+'Severity: '+detector.severity)
                self.logger.title(color+'-----------------------------------------------------')
                self.logger.title(color+'Error Message:')
                self.logger.title(color+'-----------------------------------------------------')
                self.logger.title(color+detector.error_msg)
                self.logger.title(color+'-----------------------------------------------------')
                self.logger.title(color+'Transaction sequence:')
                self.logger.title(color+'-----------------------------------------------------')
                print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, transaction_index)
        
        EquivalenceDetectorExecutor.restore_storage_snapshot(final_snapshot, env)

    @staticmethod
    def get_addresses_in_transaction(tx_output: ComputationAPIWithFuzzInfo) -> set[HexAddress]:
        addresses: set[HexAddress] = set([to_normalized_address(tx_output.msg.sender)])

        computations: deque[ComputationAPIWithFuzzInfo] = deque([tx_output])
        while len(computations) > 0:
            comp = computations.popleft()
            addresses.add(to_normalized_address(comp.msg.to))
            for child in comp.children:
                computations.append(child)

        return addresses

    @staticmethod
    def get_address_balance(address: HexAddress, env: FuzzingEnvironment) -> int:
        return env.instrumented_evm.storage_emulator.get_balance(to_canonical_address(address))

    @staticmethod
    def get_erc20_transfer_related_addresses(contract_address: HexAddress, tx_output: ComputationAPIWithFuzzInfo) -> set[HexAddress]:
        transfer_related_addresses: set[HexAddress] = set()

        for log_entry in tx_output.get_log_entries():
            event_address = to_normalized_address(log_entry[0])
            if event_address != contract_address:
                continue
            
            topic = to_hex(log_entry[1][0], 64)

            if topic[:10] == Web3.keccak(text='Transfer(address,address,uint256)')[0:4].hex():
                from_address = to_normalized_address(to_hex(log_entry[1][1], 40))
                to_address = to_normalized_address(to_hex(log_entry[1][2], 40))
                transfer_related_addresses.add(from_address)
                transfer_related_addresses.add(to_address)
        
        if to_normalized_address(ZERO_ADDRESS) in transfer_related_addresses:
            transfer_related_addresses.remove(to_normalized_address(ZERO_ADDRESS))

        return transfer_related_addresses
    
    @staticmethod
    def get_erc20_token_balance(contract_address: HexAddress, address: HexAddress, env: FuzzingEnvironment) -> int:
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
        return int.from_bytes(balance_query_result.output, 'big', signed=False) # uint256