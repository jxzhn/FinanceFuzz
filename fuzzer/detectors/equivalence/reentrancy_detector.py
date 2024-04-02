#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
from typing import TYPE_CHECKING, cast

from .base import BaseEquivalenceDetector
from utils.utils import initialize_logger
from utils import settings
from queue import Queue
from eth_utils.address import to_normalized_address
from eth_utils.hexadecimal import encode_hex
from eth_utils.exceptions import ValidationError

if TYPE_CHECKING:
    from evm.storage_emulation import ComputationAPIWithFuzzInfo, StateAPIWithFuzzInfo
    from engine.environment import FuzzingEnvironment
    from engine.components.individual import InputDict

class ReentrancyDetector(BaseEquivalenceDetector):
    def __init__(self) -> None:
        self.severity = 'High'
        self.error_msg = 'Reentrancy equivalence is violated!'

        self.logger = initialize_logger('Detector')
    
    @property
    def is_enable(self) -> bool:
        return not settings.ENVIRONMENTAL_INSTRUMENTATION
    
    def run_flavored_transaction(self, tx_input: InputDict, tx_output: ComputationAPIWithFuzzInfo, transaction_index: int, env: FuzzingEnvironment) -> bool:
        tx_input_list: list[InputDict] = []
        queue: Queue[ComputationAPIWithFuzzInfo] = Queue()
        queue.put(tx_output)
        while not queue.empty():
            computation = queue.get()
            tx_input_list.append({
                'transaction': {
                    'from': to_normalized_address(computation.msg.sender),
                    'to': to_normalized_address(computation.msg.to),
                    'value': computation.msg.value,
                    'gaslimit': computation.msg.gas,
                    'data': encode_hex(computation.msg.data)
                },
                'block': tx_input['block'],
                'global_state': tx_input['global_state'],
                'environment': tx_input['environment']
            })
            for child in computation.children:
                queue.put(child)
        
        assert env.instrumented_evm.vm is not None
        state = cast('StateAPIWithFuzzInfo', env.instrumented_evm.vm.state)
        state.forbid_internal_transactions = True

        error: bool = False
        for i, tx_in in enumerate(tx_input_list):
            try:
                result = env.instrumented_evm.deploy_transaction(tx_in, reset_balance=True if transaction_index == 0 and i == 0 else False)
                error = error or result.is_error
            except ValidationError as e:
                self.logger.error('Validation error in reentrancy detector: %s (ignoring for now)', e)
        
        state.forbid_internal_transactions = None
        return error

    def final(self, env: FuzzingEnvironment) -> bool:
        return True