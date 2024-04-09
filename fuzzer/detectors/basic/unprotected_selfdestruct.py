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

class UnprotectedSelfdestructDetector(BaseBasicDetector):
    def __init__(self) -> None:
        super().__init__()
        self.swc_id = 106
        self.severity = 'High'
        self.init()

    def init(self) -> None:
        self.trusted_arguments: str = ''

    def detect_unprotected_selfdestruct(self, current_instruction: TracedInstruction, tainted_record: TaintRecord | None, individual: Individual, transaction_index: int) -> tuple[int, int] | tuple[None, None]:
        if current_instruction['op'] in ['SELFDESTRUCT', 'SUICIDE']:
            for i in range(transaction_index):
                # Check if it is a trusted account
                if individual.solution[i]['transaction']['from'] not in settings.ATTACKER_ACCOUNTS:
                    # Add the arguments to the list of trusted arguments
                    if individual.solution[i]['transaction']['data'] not in self.trusted_arguments:
                        self.trusted_arguments += individual.solution[i]['transaction']['data']
            # An unprotected selfdestruct is detected if the sender of the transaction is an attacker and not trusted by a trusted account
            if individual.solution[transaction_index]['transaction']['from'] in settings.ATTACKER_ACCOUNTS and not individual.solution[transaction_index]['transaction']['from'].replace('0x', '') in self.trusted_arguments:
                return current_instruction['pc'], transaction_index
        return None, None
