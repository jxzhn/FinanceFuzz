#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
from typing import TYPE_CHECKING, cast

from .base import BaseEquivalenceDetector
from utils.utils import initialize_logger
from utils import settings
from eth_utils.exceptions import ValidationError

if TYPE_CHECKING:
    from evm.storage_emulation import ComputationAPIWithFuzzInfo, StateAPIWithFuzzInfo
    from engine.environment import FuzzingEnvironment
    from engine.components.individual import InputDict

class TimeDepDetector(BaseEquivalenceDetector):
    def __init__(self) -> None:
        super().__init__()
        
        self.severity = 'Medium'
        self.type = 'Timestamp Dependency'
        self.error_msg = 'Timestamp dependency equivalence is violated!'
        self.is_enable = True

        self.logger = initialize_logger('Detector')
    
    def run_flavored_transaction(self, tx_input: InputDict, tx_output: ComputationAPIWithFuzzInfo, transaction_index: int, env: FuzzingEnvironment) -> bool:
        assert env.instrumented_evm.vm is not None
        state = cast('StateAPIWithFuzzInfo', env.instrumented_evm.vm.state)
        state.random_timestamp = True

        try:
            result = env.instrumented_evm.deploy_transaction(tx_input, reset_balance=True if transaction_index == 0 else False)
        except ValidationError as e:
            self.logger.error('Validation error in timestamp dependency detector: %s (ignoring for now)', e)
        
        state.random_timestamp = None
        return True

    def final(self, env: FuzzingEnvironment) -> bool:
        return True
