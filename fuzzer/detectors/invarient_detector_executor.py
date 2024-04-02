#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING

import time

from utils.utils import print_individual_solution_as_transaction, initialize_logger

from .invarient.token_balance_detector import TokenBalanceDetector

if TYPE_CHECKING:
    from engine.components.individual import Individual, InputDict
    from engine.environment import FuzzingEnvironment, ErrorRecord
    from .invarient.base import BaseInvarientDetector
    from evm.storage_emulation import ComputationAPIWithFuzzInfo

class InvarientDetectorExecutor:
    def __init__(self, contract_types: list[str], function_signature_mapping: dict[str, str] = {}) -> None:
        self.function_signature_mapping = function_signature_mapping
        self.logger = initialize_logger('Detector')
        self.is_erc20: bool = 'ERC20' in contract_types

        self.token_balance_detector = TokenBalanceDetector(self.is_erc20)
    
    def reset_detectors(self) -> None:
        self.token_balance_detector.reset()

    @staticmethod
    def error_exists(errors: list[ErrorRecord], type: str) -> bool:
        for error in errors:
            if error['type'] == type:
                return True
        return False

    @staticmethod
    def add_error(errors: dict[str, list[ErrorRecord]], target: str, type: str, individual: Individual, env: FuzzingEnvironment, detector: BaseInvarientDetector) -> bool:
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
        elif not InvarientDetectorExecutor.error_exists(errors[target], type):
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

    def prepare_detectors(self, env: FuzzingEnvironment) -> None:
        self.reset_detectors()
        self.token_balance_detector.prepare_detect_step(env)

    def run_detectors(self, tx_input: InputDict, tx_output: ComputationAPIWithFuzzInfo, errors: dict[str, list[ErrorRecord]], individual: Individual, env: FuzzingEnvironment, transaction_index: int) -> None:
        target, error_msg = self.token_balance_detector.run_detect_step(tx_input, tx_output, env)
        if target and InvarientDetectorExecutor.add_error(errors, target, 'ERC20 Balance Invarient', individual, env, self.token_balance_detector):
            color = InvarientDetectorExecutor.get_color_for_severity(self.token_balance_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'     !!! Balance invarient violated detected !!!     ')
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'Severity: '+self.token_balance_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'Error Message:')
            self.logger.title(color+'-----------------------------------------------------')
            assert error_msg is not None
            self.logger.title(color+error_msg)
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'Transaction sequence:')
            self.logger.title(color+'-----------------------------------------------------')
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, transaction_index)