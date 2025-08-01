#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING

from .base import BaseBasicDetector
from z3 import is_expr
from z3.z3util import get_vars
from utils.utils import convert_stack_value_to_int

if TYPE_CHECKING:
    from evm.storage_emulation import TracedInstruction
    from engine.analysis.symbolic_taint_analysis import TaintRecord
    from engine.components import Individual
    from z3 import BitVecRef
    from eth_typing import HexAddress

class TransactionOrderDependencyDetector(BaseBasicDetector):
    def __init__(self) -> None:
        super().__init__()
        self.swc_id = 114
        self.severity = 'Medium'

    def init(self) -> None:
        self.sstores: dict[int, tuple[BitVecRef, str, HexAddress, int]] = {}
        self.sloads: dict[int, tuple[BitVecRef, str, HexAddress, int, int]] = {}

    def detect_transaction_order_dependency(self, current_instruction: TracedInstruction, tainted_record: TaintRecord | None, individual: Individual, transaction_index: int) -> tuple[int, int] | tuple[None, None]:
        if current_instruction['op'] == 'SSTORE':
            if tainted_record and tainted_record.stack and tainted_record.stack[-2] and is_expr(tainted_record.stack[-2][0]):
                index = convert_stack_value_to_int(current_instruction['stack'][-1])
                if index not in self.sstores:
                    self.sstores[index] = (tainted_record.stack[-2][0], individual.chromosome[transaction_index]['arguments'][0], individual.solution[transaction_index]['transaction']['from'], current_instruction['pc'])
        elif current_instruction['op'] == 'SLOAD':
            index = convert_stack_value_to_int(current_instruction['stack'][-1])
            if index in self.sstores and self.sstores[index][1] != individual.chromosome[transaction_index]['arguments'][0]:
                self.sloads[index] = (self.sstores[index][0], individual.chromosome[transaction_index]['arguments'][0], individual.solution[transaction_index]['transaction']['from'], self.sstores[index][3], transaction_index)
        elif current_instruction['op'] == 'CALL':
            if tainted_record and tainted_record.stack and tainted_record.stack[-3] and is_expr(tainted_record.stack[-3][0]):
                for index in self.sloads:
                    if index in self.sstores and bool(self.sloads[index][0] == tainted_record.stack[-3][0]) and self.sloads[index][1] == individual.chromosome[transaction_index]['arguments'][0]:
                        return self.sloads[index][3], self.sloads[index][4]
            if tainted_record and tainted_record.stack and tainted_record.stack[-2]:
                value = convert_stack_value_to_int(current_instruction['stack'][-3])
                if value > 0 or tainted_record and tainted_record.stack and tainted_record.stack[-3]:
                    for i in range(transaction_index+1, len(individual.chromosome)):
                        if self.sstores and individual.chromosome[transaction_index]['arguments'] == individual.chromosome[i]['arguments'] and individual.solution[transaction_index]['transaction']['from'] != individual.solution[i]['transaction']['from']:
                            return list(self.sstores.values())[0][-1], transaction_index
        return None, None
