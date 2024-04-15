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
        tx_list: list[tuple[InputDict, deque[tuple[bytes, int]]]] = []

        queue: deque[ComputationAPIWithFuzzInfo] = deque()
        queue.append(tx_output)
        while len(queue) > 0:
            computation = queue.popleft()
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
            retvals: deque[tuple[bytes, int]] = deque()
            for child in computation.children:
                queue.append(child)
                retvals.append((child.return_data, 1 if child.is_success else 0))
            tx_list.append((tx, retvals))
        
        assert env.instrumented_evm.vm is not None
        state = cast('StateAPIWithFuzzInfo', env.instrumented_evm.vm.state)
        state.forbid_internal_transactions = True

        for i, (tx, retvals) in enumerate(tx_list):
            state.internal_return_values = retvals
            if i != 0:
                tx_data = decode_hex(tx['transaction']['data'])
                num_zeros = tx_data.count(b'\x00')
                num_nonzeros = len(tx_data) - num_zeros
                tx['transaction']['gaslimit'] += GAS_TX + num_zeros * GAS_TXDATAZERO + num_nonzeros * GAS_TXDATANONZERO
            try:
                result = env.instrumented_evm.deploy_transaction(tx, reset_balance=True if transaction_index == 0 and i == 0 else False)
            except ValidationError as e:
                self.logger.error('Validation error in reentrancy detector: %s (ignoring for now)', e)
        
        state.forbid_internal_transactions = None
        state.internal_return_values = None
        return True

    def final(self, env: FuzzingEnvironment) -> bool:
        return True
