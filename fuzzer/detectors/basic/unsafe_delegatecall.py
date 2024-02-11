#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING

from .base import BaseBasicDetector
from z3 import is_expr
from utils import settings

if TYPE_CHECKING:
    from evm.storage_emulation import TracedInstruction
    from engine.analysis.symbolic_taint_analysis import TaintRecord
    from engine.components import Individual

class UnsafeDelegatecallDetector(BaseBasicDetector):
    def __init__(self) -> None:
        self.swc_id = 112
        self.severity = 'High'
        self.init()

    def init(self) -> None:
        self.delegatecall: tuple[int, int] | tuple[None, None] = None, None

    def detect_unsafe_delegatecall(self, current_instruction: TracedInstruction, tainted_record: TaintRecord | None, individual: Individual, previous_instruction: TracedInstruction | None, transaction_index: int) -> tuple[int, int] | tuple[None, None]:
        if current_instruction['op'] == 'DELEGATECALL':
            if tainted_record and tainted_record.stack[-2] and is_expr(tainted_record.stack[-2][0]):
                for index in range(len(individual.solution)):
                    if individual.solution[index]['transaction']['from'] not in settings.ATTACKER_ACCOUNTS:
                        return None, None
                self.delegatecall = current_instruction['pc'], transaction_index
        elif current_instruction['op'] == 'STOP' and self.delegatecall:
            return self.delegatecall
        return None, None
