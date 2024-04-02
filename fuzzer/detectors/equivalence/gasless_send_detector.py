#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
from typing import TYPE_CHECKING, cast

from .base import BaseEquivalenceDetector
from utils.utils import initialize_logger
from eth_utils.exceptions import ValidationError

if TYPE_CHECKING:
    from evm.storage_emulation import ComputationAPIWithFuzzInfo, StateAPIWithFuzzInfo
    from engine.environment import FuzzingEnvironment
    from engine.components.individual import InputDict

class GaslessSendDetector(BaseEquivalenceDetector):
    def __init__(self) -> None:
        self.severity = 'High'
        self.error_msg = 'Gasless send equivalence is violated!'

        self.logger = initialize_logger('Detector')
    
    @property
    def is_enable(self) -> bool:
        return True
    
    def run_flavored_transaction(self, tx_input: InputDict, tx_output: ComputationAPIWithFuzzInfo, transaction_index: int, env: FuzzingEnvironment) -> bool:
        assert env.instrumented_evm.vm is not None
        state = cast('StateAPIWithFuzzInfo', env.instrumented_evm.vm.state)
        state.zero_call_gas = True

        try:
            result = env.instrumented_evm.deploy_transaction(tx_input, reset_balance=True if transaction_index == 0 else False)
        except ValidationError as e:
            self.logger.error('Validation error in gasless send detector: %s (ignoring for now)', e)
        
        state.zero_call_gas = None
        return result.is_error

    def final(self, env: FuzzingEnvironment) -> bool:
        return True