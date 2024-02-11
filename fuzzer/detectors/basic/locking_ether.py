#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING

from .base import BaseBasicDetector

if TYPE_CHECKING:
    from utils.control_flow_graph import ControlFlowGraph
    from evm.storage_emulation import TracedInstruction
    from engine.components import Individual

class LockingEtherDetector(BaseBasicDetector):
    def __init__(self) -> None:
        self.swc_id = 132
        self.severity = 'Medium'

    def init(self) -> None:
        pass

    def detect_locking_ether(self, cfg: ControlFlowGraph, current_instruction: TracedInstruction, individual: Individual, transaction_index: int) -> tuple[int, int] | tuple[None, None]:
        # Check if we cannot send ether
        if not cfg.can_send_ether:
            # Check if we can receive ether
            if current_instruction['op'] == 'STOP' and individual.solution[transaction_index]['transaction']['value'] > 0:
                return current_instruction['pc'], transaction_index
        return None, None
