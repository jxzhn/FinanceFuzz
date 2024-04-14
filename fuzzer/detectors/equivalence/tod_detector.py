#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
from typing import TYPE_CHECKING

from .base import BaseEquivalenceDetector
from utils.utils import initialize_logger
from collections import deque
import random
from eth_utils.exceptions import ValidationError

if TYPE_CHECKING:
    from evm.storage_emulation import ComputationAPIWithFuzzInfo
    from engine.environment import FuzzingEnvironment
    from engine.components.individual import InputDict
    from eth_typing import HexAddress

class TODDetector(BaseEquivalenceDetector):
    def __init__(self) -> None:
        super().__init__()
        
        self.severity = 'Medium'
        self.type = 'Transaction Order Dependency'
        self.error_msg = 'Transaction order dependency equivalence is violated!'
        self.is_enable = True

        self.logger = initialize_logger('Detector')
        self.sender_tx_map: dict[HexAddress, deque[InputDict]] = {}
    
    def run_flavored_transaction(self, tx_input: InputDict, tx_output: ComputationAPIWithFuzzInfo, transaction_index: int, env: FuzzingEnvironment) -> bool:
        sender = tx_input['transaction']['from']
        if sender not in self.sender_tx_map:
            self.sender_tx_map[sender] = deque()
        self.sender_tx_map[sender].append(tx_input)
        return True

    def final(self, env: FuzzingEnvironment) -> bool:
        tx_input_list: list[InputDict] = []
        while len(self.sender_tx_map) > 0:
            sender = random.choice(list(self.sender_tx_map.keys()))
            tx_input_list.append(self.sender_tx_map[sender].popleft())
            if len(self.sender_tx_map[sender]) == 0:
                del self.sender_tx_map[sender]
        
        for transaction_index, tx_input in enumerate(tx_input_list):
            try:
                result = env.instrumented_evm.deploy_transaction(tx_input, reset_balance=True if transaction_index == 0 else False)
            except ValidationError as e:
                self.logger.error('Validation error in transaction order dependency detector: %s (ignoring for now)', e)
        
        return True
