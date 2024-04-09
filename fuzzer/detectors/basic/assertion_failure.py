#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING

from .base import BaseBasicDetector

if TYPE_CHECKING:
    from evm.storage_emulation import TracedInstruction

class AssertionFailureDetector(BaseBasicDetector):
    def __init__(self) -> None:
        super().__init__()
        self.swc_id = 110
        self.severity = 'Medium'
        self.init()
    
    def init(self) -> None:
        pass

    def detect_assertion_failure(self, current_instruction: TracedInstruction, transaction_index: int) -> tuple[int, int] | tuple[None, None]:
        if current_instruction['op'] in ['ASSERTFAIL', 'INVALID']:
            return current_instruction['pc'], transaction_index
        return None, None
