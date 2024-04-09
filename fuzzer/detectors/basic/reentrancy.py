#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING

from .base import BaseBasicDetector
from z3 import simplify
from utils.utils import convert_stack_value_to_int

if TYPE_CHECKING:
    from engine.analysis.symbolic_taint_analysis import TaintRecord
    from evm.storage_emulation import TracedInstruction

class ReentrancyDetector(BaseBasicDetector):
    def __init__(self) -> None:
        super().__init__()
        self.swc_id = 107
        self.severity = 'High'
        self.init()

    def init(self) -> None:
        self.sloads: dict[int, tuple[int, int]] = {}
        self.calls: set[tuple[int, int]] = set()

    def detect_reentrancy(self, tainted_record: TaintRecord | None, current_instruction: TracedInstruction, transaction_index: int) -> tuple[int, int] | tuple[None, None]:
        # Remember sloads
        if current_instruction['op'] == 'SLOAD':
            if tainted_record and tainted_record.stack and tainted_record.stack[-1]:
                storage_index = convert_stack_value_to_int(current_instruction['stack'][-1])
                self.sloads[storage_index] = current_instruction['pc'], transaction_index
        # Remember calls with more than 2300 gas and where the value is larger than zero/symbolic or where destination is symbolic
        elif current_instruction['op'] == 'CALL' and self.sloads:
            gas = convert_stack_value_to_int(current_instruction['stack'][-1])
            value = convert_stack_value_to_int(current_instruction['stack'][-3])
            if gas > 2300 and (value > 0 or tainted_record and tainted_record.stack and tainted_record.stack[-3]):
                self.calls.add((current_instruction['pc'], transaction_index))
            if gas > 2300 and tainted_record and tainted_record.stack and tainted_record.stack[-2]:
                self.calls.add((current_instruction['pc'], transaction_index))
                for pc, index in self.sloads.values():
                    if pc < current_instruction['pc']:
                        return current_instruction['pc'], index
        # Check if this sstore is happening after a call and if it is happening after an sload which shares the same storage index
        elif current_instruction['op'] == 'SSTORE' and self.calls:
            if tainted_record and tainted_record.stack and tainted_record.stack[-1]:
                storage_index = convert_stack_value_to_int(current_instruction['stack'][-1])
                if storage_index in self.sloads:
                    for pc, index in self.calls:
                        if pc < current_instruction['pc']:
                            return pc, index
        # Clear sloads and calls from previous transactions
        elif current_instruction['op'] in ['STOP', 'RETURN', 'REVERT', 'ASSERTFAIL', 'INVALID', 'SUICIDE', 'SELFDESTRUCT']:
            self.sloads = {}
            self.calls = set()
        return None, None
