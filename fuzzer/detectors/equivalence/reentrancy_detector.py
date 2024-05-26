#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
from typing import TYPE_CHECKING, cast

from .base import BaseEquivalenceDetector
from utils.utils import initialize_logger
from utils import settings
from collections import deque
from eth_utils.address import to_normalized_address
from eth_utils.hexadecimal import encode_hex, decode_hex
from eth_utils.exceptions import ValidationError
from eth.constants import GAS_TX, GAS_TXDATAZERO, GAS_TXDATANONZERO

if TYPE_CHECKING:
    from evm.storage_emulation import ComputationAPIWithFuzzInfo, StateAPIWithFuzzInfo
    from engine.environment import FuzzingEnvironment
    from engine.components.individual import InputDict

class ReentrancyDetector(BaseEquivalenceDetector):
    def __init__(self) -> None:
        super().__init__()
        
        self.severity = 'High'
        self.type = 'Reentrancy'
        self.error_msg = 'Reentrancy equivalence is violated!'
        self.is_enable = not settings.ENVIRONMENTAL_INSTRUMENTATION

        self.logger = initialize_logger('Detector')
    
    def run_flavored_transaction(self, tx_input: InputDict, tx_output: ComputationAPIWithFuzzInfo, transaction_index: int, env: FuzzingEnvironment) -> bool:
        # tx, retvals (return data, is_success, gas_used)
        tx_list: list[tuple[InputDict, deque[tuple[bytes, int, int]]]] = []

        queue: deque[ComputationAPIWithFuzzInfo] = deque()
        queue.append(tx_output)
        while len(queue) > 0:
            computation = queue.popleft()

            if computation.is_error:
                continue

            tx: InputDict = {
                'transaction': {
                    'from': to_normalized_address(computation.msg.sender),
                    'to': to_normalized_address(computation.msg.to),
                    'value': computation.msg.value,
                    'gaslimit': computation.msg.gas,
                    'data': encode_hex(bytes(computation.msg.data))
                },
                'block': tx_input['block'],
                'global_state': tx_input['global_state'],
                'environment': tx_input['environment']
            }

            retvals: deque[tuple[bytes, int, int]] = deque()
            for child in computation.children:
                queue.append(child)
                retvals.append((child.return_data, 1 if child.is_success else 0, child.get_gas_used()))
            
            tx_list.append((tx, retvals))
        
        assert env.instrumented_evm.vm is not None
        state = cast('StateAPIWithFuzzInfo', env.instrumented_evm.vm.state)
        state.forbid_internal_transactions = True
        state.forbided_transactions = deque([tx_list[0][0]] if len(tx_list) != 0 else [])

        if transaction_index == 0:
            env.instrumented_evm.reset_balance()
        
        failed_flag = False
        for i, (tx, retvals) in enumerate(tx_list):
            if len(state.forbided_transactions) == 0:
                break
            _tx = state.forbided_transactions.popleft()
            if _tx['transaction']['from'] != tx['transaction']['from'] or _tx['transaction']['to'] != tx['transaction']['to']:
                self.logger.error('Transaction mismatch in reentrancy detector: %s != %s, skip detecting', _tx, tx)
                failed_flag = True
                break
            tx['transaction']['value'] = _tx['transaction']['value']
            tx['transaction']['data'] = _tx['transaction']['data']

            if i != 0:
                tx_data = decode_hex(tx['transaction']['data'])
                num_zeros = tx_data.count(b'\x00')
                num_nonzeros = len(tx_data) - num_zeros
                tx['transaction']['gaslimit'] += GAS_TX + num_zeros * GAS_TXDATAZERO + num_nonzeros * GAS_TXDATANONZERO
            
            state.internal_return_values = retvals
            try:
                # TODO: it seems that the gas consumed has something wrong
                result = env.instrumented_evm.deploy_transaction(tx, no_reentrancy_tx_data=i != 0)
            except ValidationError as e:
                self.logger.error('Validation error in reentrancy detector: %s (ignoring for now)', e)
        
        state.forbid_internal_transactions = None
        state.internal_return_values = None
        return not failed_flag

    def final(self, env: FuzzingEnvironment) -> bool:
        return True
