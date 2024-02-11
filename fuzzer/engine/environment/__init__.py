#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING, Literal, TypedDict, NotRequired

from dataclasses import dataclass, field

if TYPE_CHECKING:
    from evm import InstrumentedEVM
    from z3 import Solver, ExprRef
    from engine.analysis.symbolic_taint_analysis import SymbolicTaintAnalyzer
    from engine.analysis.execution_trace_analysis import VisitedBranchRecord
    from detectors import BasicDetectorExecutor, InvarientDetectorExecutor
    import argparse
    from utils.control_flow_graph import ControlFlowGraph
    from engine.components import Population
    from engine.components.individual import InputDict
    from eth_typing import Address, HexAddress

GenerationRecord = TypedDict('GenerationRecord', {
    'generation': int,
    'time': float,
    'total_transactions': int,
    'unique_transactions': int,
    'code_coverage': float,
    'branch_coverage': float,
})

TransactionRecord = TypedDict('TransactionRecord', {
    'total': int,
    'per_second': float,
})

CodeCoverageRecord = TypedDict('CodeCoverageRecord', {
    'percentage': float,
    'covered': int,
    'total': int,
    'covered_with_children': int,
    'total_with_children': int,
})

BranchCoverageRecord = TypedDict('BranchCoverageRecord', {
    'percentage': float,
    'covered': int,
    'total': int,
})

ErrorRecord = TypedDict('ErrorRecord', {
    'swc_id': int,
    'severity': str,
    'type': str,
    'individual': list['InputDict'],
    'time': float,
    'line': NotRequired[int],
    'column': NotRequired[int],
    'source_code': NotRequired[str],
})

FuzzResult = TypedDict('FuzzResult', {
    'generations': list[GenerationRecord],
    'errors': dict[int, list[ErrorRecord]],
    'advanced_errors': dict[str, list[ErrorRecord]],
    'transactions': TransactionRecord,
    'code_coverage': CodeCoverageRecord,
    'branch_coverage': BranchCoverageRecord,
    'execution_time': float,
    'memory_consumption': float,
    'address_under_test': 'HexAddress',
    'seed': float,
}, total=False)


@dataclass
class FuzzingEnvironment:
    contract_name: str
    instrumented_evm: InstrumentedEVM
    solver: Solver
    results: FuzzResult
    symbolic_taint_analyzer: SymbolicTaintAnalyzer
    detector_executor: BasicDetectorExecutor
    invarient_detector_executor: InvarientDetectorExecutor
    interface: dict[str, list[str]]
    overall_pcs: list[int]
    overall_jumpis: list[int]
    len_overall_pcs_with_children: int
    other_contracts: list[Address]
    args: argparse.Namespace
    seed: float
    cfg: ControlFlowGraph
    abi: dict
    
    nr_of_transactions: int = 0
    unique_individuals: set[str] = field(default_factory=set)
    code_coverage: set[str] = field(default_factory=set)
    children_code_coverage: dict[Address, set[int]] = field(default_factory=dict)
    previous_code_coverage_length: int = 0
    visited_branches: dict[str, dict[int, VisitedBranchRecord]] = field(default_factory=dict)
    memoized_fitness: dict = field(default_factory=dict)
    memoized_storage: dict = field(default_factory=dict)
    memoized_symbolic_execution: dict[ExprRef, bool] = field(default_factory=dict)
    individual_branches: dict[str, dict[str, dict[str, bool]]] = field(default_factory=dict)
    data_dependencies: dict[str, dict[Literal['read', 'write'], set[int]]] = field(default_factory=dict)
    execution_begin: float | None = None
    population: Population | None = None