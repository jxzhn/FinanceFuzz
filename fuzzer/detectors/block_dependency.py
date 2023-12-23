#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING

from .base import BaseDetector
from utils.utils import convert_stack_value_to_int

if TYPE_CHECKING:
    from engine.analysis.symbolic_taint_analysis import TaintRecord
    from evm.storage_emulation import TracedInstruction
    from z3 import BoolRef

class BlockDependencyDetector(BaseDetector):
    def __init__(self) -> None:
        self.swc_id = 120
        self.severity = 'Low'
        self.init()
    
    def init(self) -> None:
        self.block_instruction: tuple[int, int] | tuple[None, None] = None, None
        self.block_dependency: bool = False

    def detect_block_dependency(self, tainted_record: TaintRecord | None, current_instruction: TracedInstruction, previous_branch: list[BoolRef], transaction_index: int) -> tuple[int, int] | tuple[None, None]:
        # Check for a call with transfer of ether (check if amount is greater than zero or symbolic)
        if current_instruction['op'] == 'CALL' and (convert_stack_value_to_int(current_instruction['stack'][-3]) or tainted_record and tainted_record.stack[-3]) or \
           current_instruction['op'] in ['STATICCALL', 'SELFDESTRUCT', 'SUICIDE', 'CREATE', 'DELEGATECALL']:
            # Check if there is a block dependency by analyzing previous branch expression
            for expression in previous_branch:
                if 'blockhash' in str(expression) or \
                   'coinbase' in str(expression) or \
                   'timestamp' in str(expression) or \
                   'number' in str(expression) or \
                   'difficulty' in str(expression) or \
                   'gaslimit' in str(expression):
                   self.block_dependency = True
        # Check if block related information flows into condition
        elif current_instruction and current_instruction['op'] in ['LT', 'GT', 'SLT', 'SGT', 'EQ']:
            if tainted_record and tainted_record.stack:
                if tainted_record.stack[-1]:
                    for expression in tainted_record.stack[-1]:
                        if 'blockhash' in str(expression) or \
                           'coinbase' in str(expression) or \
                           'timestamp' in str(expression) or \
                           'number' in str(expression) or \
                           'difficulty' in str(expression) or \
                           'gaslimit' in str(expression):
                           self.block_dependency = True
                if tainted_record.stack[-2]:
                    for expression in tainted_record.stack[-2]:
                        if 'blockhash' in str(expression) or \
                           'coinbase' in str(expression) or \
                           'timestamp' in str(expression) or \
                           'number' in str(expression) or \
                           'difficulty' in str(expression) or \
                           'gaslimit' in str(expression):
                           self.block_dependency = True
        # Register block related information
        elif current_instruction['op'] in ['BLOCKHASH', 'COINBASE', 'TIMESTAMP', 'NUMBER', 'DIFFICULTY', 'GASLIMIT']:
            self.block_instruction = current_instruction['pc'], transaction_index
        # Check if execution stops withour exception
        if self.block_dependency and current_instruction['op'] in ['STOP', 'SELFDESTRUCT', 'RETURN']:
            return self.block_instruction
        return None, None
