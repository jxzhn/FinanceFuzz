#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
from typing import TYPE_CHECKING

from fuzzer.engine.environment import FuzzingEnvironment

from .base import BaseEquivalenceDetector
from utils.utils import initialize_logger
import random
from eth_utils.exceptions import ValidationError

if TYPE_CHECKING:
    from evm.storage_emulation import ComputationAPIWithFuzzInfo
    from engine.environment import FuzzingEnvironment
    from engine.components.individual import InputDict

class TODDetector(BaseEquivalenceDetector):
    def __init__(self) -> None:
        self.severity = 'Medium'
        self.error_msg = 'Transaction order dependency equivalence is violated!'

        self.logger = initialize_logger('Detector')
        self.tx_input_list = []
    
    @property
    def is_enable(self) -> bool:
        return True
    
    def run_flavored_transaction(self, tx_input: InputDict, tx_output: ComputationAPIWithFuzzInfo, transaction_index: int, env: FuzzingEnvironment) -> bool:
        self.tx_input_list.append(tx_input)
        return True

    def final(self, env: FuzzingEnvironment) -> bool:
        random.shuffle(self.tx_input_list)

        error: bool = False
        for transaction_index, tx_input in enumerate(self.tx_input_list):
            try:
                result = env.instrumented_evm.deploy_transaction(tx_input, reset_balance=True if transaction_index == 0 else False)
            except ValidationError as e:
                self.logger.error('Validation error in transaction order dependency detector: %s (ignoring for now)', e)
            error = error or result.is_error
        
        return error