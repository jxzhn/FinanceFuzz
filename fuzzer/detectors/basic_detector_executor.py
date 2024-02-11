#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING

import time

from utils.utils import print_individual_solution_as_transaction, initialize_logger

from .basic.integer_overflow import IntegerOverflowDetector
from .basic.assertion_failure import AssertionFailureDetector
from .basic.arbitrary_memory_access import ArbitraryMemoryAccessDetector
from .basic.reentrancy import ReentrancyDetector
from .basic.transaction_order_dependency import TransactionOrderDependencyDetector
from .basic.block_dependency import BlockDependencyDetector
from .basic.unchecked_return_value import UncheckedReturnValueDetector
from .basic.unsafe_delegatecall import UnsafeDelegatecallDetector
from .basic.leaking_ether import LeakingEtherDetector
from .basic.locking_ether import LockingEtherDetector
from .basic.unprotected_selfdestruct import UnprotectedSelfdestructDetector

if TYPE_CHECKING:
    from utils.source_map import SourceMap
    from engine.components.individual import Individual
    from engine.environment import FuzzingEnvironment, ErrorRecord
    from .basic.base import BaseBasicDetector
    from evm.storage_emulation import TracedInstruction
    from engine.analysis.symbolic_taint_analysis import TaintRecord
    from z3 import BoolRef


class BasicDetectorExecutor:
    def __init__(self, source_map: SourceMap | None = None, function_signature_mapping: dict[str, str] = {}) -> None:
        self.source_map = source_map
        self.function_signature_mapping = function_signature_mapping
        self.logger = initialize_logger('Detector')

        self.integer_overflow_detector = IntegerOverflowDetector()
        self.assertion_failure_detector = AssertionFailureDetector()
        self.arbitrary_memory_access_detector = ArbitraryMemoryAccessDetector()
        self.reentrancy_detector = ReentrancyDetector()
        self.transaction_order_dependency_detector = TransactionOrderDependencyDetector()
        self.block_dependency_detector = BlockDependencyDetector()
        self.unchecked_return_value_detector = UncheckedReturnValueDetector()
        self.unsafe_delegatecall_detector = UnsafeDelegatecallDetector()
        self.leaking_ether_detector = LeakingEtherDetector()
        self.locking_ether_detector = LockingEtherDetector()
        self.unprotected_selfdestruct_detector = UnprotectedSelfdestructDetector()

    def initialize_detectors(self) -> None:
        self.integer_overflow_detector.init()
        self.assertion_failure_detector.init()
        self.arbitrary_memory_access_detector.init()
        self.reentrancy_detector.init()
        self.transaction_order_dependency_detector.init()
        self.block_dependency_detector.init()
        self.unchecked_return_value_detector.init()
        self.unsafe_delegatecall_detector.init()
        self.leaking_ether_detector.init()
        self.locking_ether_detector.init()
        self.unprotected_selfdestruct_detector.init()

    @staticmethod
    def error_exists(errors: list[ErrorRecord], type: str) -> bool:
        for error in errors:
            if error['type'] == type:
                return True
        return False

    @staticmethod
    def add_error(errors: dict[int, list[ErrorRecord]], pc: int, type: str, individual: Individual, mfe: FuzzingEnvironment, detector: BaseBasicDetector, source_map: SourceMap | None) -> bool:
        assert mfe.execution_begin is not None
        error: ErrorRecord = {
            'swc_id': detector.swc_id,
            'severity': detector.severity,
            'type': type,
            'individual': individual.solution,
            'time': time.time() - mfe.execution_begin,
        }
        if source_map and source_map.get_buggy_line(pc):
            start_location = source_map.get_location(pc)['begin']
            assert start_location is not None
            error['line'] = start_location['line'] + 1
            error['column'] = start_location['column'] + 1
            error['source_code'] = source_map.get_buggy_line(pc)
        if not pc in errors:
            errors[pc] = [error]
            return True
        elif not BasicDetectorExecutor.error_exists(errors[pc], type):
            errors[pc].append(error)
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

    def run_detectors(self, previous_instruction: TracedInstruction | None, current_instruction: TracedInstruction, errors: dict[int, list[ErrorRecord]], tainted_record: TaintRecord | None, individual: Individual, mfe: FuzzingEnvironment, previous_branch: list[BoolRef], transaction_index: int) -> None:
        pc, index = self.arbitrary_memory_access_detector.detect_arbitrary_memory_access(tainted_record, individual, current_instruction, transaction_index)
        if pc and BasicDetectorExecutor.add_error(errors, pc, 'Arbitrary Memory Access', individual, mfe, self.arbitrary_memory_access_detector, self.source_map):
            color = BasicDetectorExecutor.get_color_for_severity( self.arbitrary_memory_access_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'      !!! Arbitrary memory access detected !!!       ')
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'SWC-ID:   '+str(self.arbitrary_memory_access_detector.swc_id))
            self.logger.title(color+'Severity: '+self.arbitrary_memory_access_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+'Source code line:')
                self.logger.title(color+'-----------------------------------------------------')
                begin_location = self.source_map.get_location(pc)['begin']
                assert begin_location is not None
                line = begin_location['line'] + 1
                column = begin_location['column'] + 1
                self.logger.title(color+self.source_map.source.filename+':'+str(line)+':'+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'Transaction sequence:')
            self.logger.title(color+'-----------------------------------------------------')
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        pc, index = self.assertion_failure_detector.detect_assertion_failure(current_instruction, transaction_index)
        if pc and BasicDetectorExecutor.add_error(errors, pc, 'Assertion Failure', individual, mfe, self.assertion_failure_detector, self.source_map):
            color = BasicDetectorExecutor.get_color_for_severity(self.assertion_failure_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'          !!! Assertion failure detected !!!         ')
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'SWC-ID:   '+str(self.assertion_failure_detector.swc_id))
            self.logger.title(color+'Severity: '+self.assertion_failure_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+'Source code line:')
                self.logger.title(color+'-----------------------------------------------------')
                begin_location = self.source_map.get_location(pc)['begin']
                assert begin_location is not None
                line = begin_location['line'] + 1
                column = begin_location['column'] + 1
                self.logger.title(color+self.source_map.source.filename+':'+str(line)+':'+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'Transaction sequence:')
            self.logger.title(color+'-----------------------------------------------------')
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        pc, index, type = self.integer_overflow_detector.detect_integer_overflow(mfe, tainted_record, previous_instruction, current_instruction, individual, transaction_index)
        if pc and BasicDetectorExecutor.add_error(errors, pc, 'Integer Overflow', individual, mfe, self.integer_overflow_detector, self.source_map):
            color = BasicDetectorExecutor.get_color_for_severity(self.integer_overflow_detector.severity)
            if type == 'overflow':
                self.logger.title(color+'-----------------------------------------------------')
                self.logger.title(color+'          !!! Integer overflow detected !!!          ')
                self.logger.title(color+'-----------------------------------------------------')
            else:
                self.logger.title(color+'-----------------------------------------------------')
                self.logger.title(color+'          !!! Integer underflow detected !!!          ')
                self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'SWC-ID:   '+str(self.integer_overflow_detector.swc_id))
            self.logger.title(color+'Severity: '+self.integer_overflow_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+'Source code line:')
                self.logger.title(color+'-----------------------------------------------------')
                begin_location = self.source_map.get_location(pc)['begin']
                assert begin_location is not None
                line = begin_location['line'] + 1
                column = begin_location['column'] + 1
                self.logger.title(color+self.source_map.source.filename+':'+str(line)+':'+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'Transaction sequence:')
            self.logger.title(color+'-----------------------------------------------------')
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        pc, index = self.reentrancy_detector.detect_reentrancy(tainted_record, current_instruction, transaction_index)
        if pc and BasicDetectorExecutor.add_error(errors, pc, 'Reentrancy', individual, mfe, self.reentrancy_detector, self.source_map):
            color = BasicDetectorExecutor.get_color_for_severity(self.reentrancy_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'            !!! Reentrancy detected !!!              ')
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'SWC-ID:   '+str(self.reentrancy_detector.swc_id))
            self.logger.title(color+'Severity: '+self.reentrancy_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+'Source code line:')
                self.logger.title(color+'-----------------------------------------------------')
                begin_location = self.source_map.get_location(pc)['begin']
                assert begin_location is not None
                line = begin_location['line'] + 1
                column = begin_location['column'] + 1
                self.logger.title(color+self.source_map.source.filename+':'+str(line)+':'+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'Transaction sequence:')
            self.logger.title(color+'-----------------------------------------------------')
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        pc, index = self.transaction_order_dependency_detector.detect_transaction_order_dependency(current_instruction, tainted_record, individual, transaction_index)
        if pc and BasicDetectorExecutor.add_error(errors, pc, 'Transaction Order Dependency', individual, mfe, self.transaction_order_dependency_detector, self.source_map):
            color = BasicDetectorExecutor.get_color_for_severity(self.transaction_order_dependency_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'    !!! Transaction order dependency detected !!!    ')
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'SWC-ID:   '+str(self.transaction_order_dependency_detector.swc_id))
            self.logger.title(color+'Severity: '+self.transaction_order_dependency_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+'Source code line:')
                self.logger.title(color+'-----------------------------------------------------')
                begin_location = self.source_map.get_location(pc)['begin']
                assert begin_location is not None
                line = begin_location['line'] + 1
                column = begin_location['column'] + 1
                self.logger.title(color+self.source_map.source.filename+':'+str(line)+':'+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'Transaction sequence:')
            self.logger.title(color+'-----------------------------------------------------')
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        pc, index = self.block_dependency_detector.detect_block_dependency(tainted_record, current_instruction, previous_branch, transaction_index)
        if pc and BasicDetectorExecutor.add_error(errors, pc, 'Block Dependency', individual, mfe, self.block_dependency_detector, self.source_map):
            color = BasicDetectorExecutor.get_color_for_severity(self.block_dependency_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'          !!! Block dependency detected !!!          ')
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'SWC-ID:   '+str(self.block_dependency_detector.swc_id))
            self.logger.title(color+'Severity: '+self.block_dependency_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+'Source code line:')
                self.logger.title(color+'-----------------------------------------------------')
                begin_location = self.source_map.get_location(pc)['begin']
                assert begin_location is not None
                line = begin_location['line'] + 1
                column = begin_location['column'] + 1
                self.logger.title(color+self.source_map.source.filename+':'+str(line)+':'+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'Transaction sequence:')
            self.logger.title(color+'-----------------------------------------------------')
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        pc, index = self.unchecked_return_value_detector.detect_unchecked_return_value(previous_instruction, current_instruction, tainted_record, transaction_index)
        if pc and BasicDetectorExecutor.add_error(errors, pc, 'Unchecked Return Value', individual, mfe, self.unchecked_return_value_detector, self.source_map):
            color = BasicDetectorExecutor.get_color_for_severity(self.unchecked_return_value_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'        !!! Unchecked return value detected !!!         ')
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'SWC-ID:   '+str(self.unchecked_return_value_detector.swc_id))
            self.logger.title(color+'Severity: '+self.unchecked_return_value_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+'Source code line:')
                self.logger.title(color+'-----------------------------------------------------')
                begin_location = self.source_map.get_location(pc)['begin']
                assert begin_location is not None
                line = begin_location['line'] + 1
                column = begin_location['column'] + 1
                self.logger.title(color+self.source_map.source.filename+':'+str(line)+':'+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'Transaction sequence:')
            self.logger.title(color+'-----------------------------------------------------')
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        pc, index = self.unsafe_delegatecall_detector.detect_unsafe_delegatecall(current_instruction, tainted_record, individual, previous_instruction, transaction_index)
        if pc and BasicDetectorExecutor.add_error(errors, pc, 'Unsafe Delegatecall', individual, mfe, self.unsafe_delegatecall_detector, self.source_map):
            color = BasicDetectorExecutor.get_color_for_severity(self.unsafe_delegatecall_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'        !!! Unsafe delegatecall detected !!!         ')
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'SWC-ID:   '+str(self.unsafe_delegatecall_detector.swc_id))
            self.logger.title(color+'Severity: '+self.unsafe_delegatecall_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+'Source code line:')
                self.logger.title(color+'-----------------------------------------------------')
                begin_location = self.source_map.get_location(pc)['begin']
                assert begin_location is not None
                line = begin_location['line'] + 1
                column = begin_location['column'] + 1
                self.logger.title(color+self.source_map.source.filename+':'+str(line)+':'+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'Transaction sequence:')
            self.logger.title(color+'-----------------------------------------------------')
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        pc, index = self.leaking_ether_detector.detect_leaking_ether(current_instruction, tainted_record, individual, transaction_index, previous_branch)
        if pc and BasicDetectorExecutor.add_error(errors, pc, 'Leaking Ether', individual, mfe, self.leaking_ether_detector, self.source_map):
            color = BasicDetectorExecutor.get_color_for_severity(self.leaking_ether_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'           !!! Leaking ether detected !!!            ')
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'SWC-ID:   '+str(self.leaking_ether_detector.swc_id))
            self.logger.title(color+'Severity: '+self.leaking_ether_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+'Source code line:')
                self.logger.title(color+'-----------------------------------------------------')
                begin_location = self.source_map.get_location(pc)['begin']
                assert begin_location is not None
                line = begin_location['line'] + 1
                column = begin_location['column'] + 1
                self.logger.title(color+self.source_map.source.filename+':'+str(line)+':'+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'Transaction sequence:')
            self.logger.title(color+'-----------------------------------------------------')
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        pc, index = self.locking_ether_detector.detect_locking_ether(mfe.cfg, current_instruction, individual, transaction_index)
        if pc and BasicDetectorExecutor.add_error(errors, pc, 'Locking Ether', individual, mfe, self.locking_ether_detector, self.source_map):
            color = BasicDetectorExecutor.get_color_for_severity(self.locking_ether_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'           !!! Locking ether detected !!!            ')
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'SWC-ID:   '+str(self.locking_ether_detector.swc_id))
            self.logger.title(color+'Severity: '+self.locking_ether_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+'Source code line:')
                self.logger.title(color+'-----------------------------------------------------')
                begin_location = self.source_map.get_location(pc)['begin']
                assert begin_location is not None
                line = begin_location['line'] + 1
                column = begin_location['column'] + 1
                self.logger.title(color+self.source_map.source.filename+':'+str(line)+':'+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'Transaction sequence:')
            self.logger.title(color+'-----------------------------------------------------')
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        pc, index = self.unprotected_selfdestruct_detector.detect_unprotected_selfdestruct(current_instruction, tainted_record, individual, transaction_index)
        if pc and BasicDetectorExecutor.add_error(errors, pc, 'Unprotected Selfdestruct', individual, mfe, self.unprotected_selfdestruct_detector, self.source_map):
            color = BasicDetectorExecutor.get_color_for_severity(self.unprotected_selfdestruct_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'      !!! Unprotected selfdestruct detected !!!      ')
            self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'SWC-ID:   '+str(self.unprotected_selfdestruct_detector.swc_id))
            self.logger.title(color+'Severity: '+self.unprotected_selfdestruct_detector.severity)
            self.logger.title(color+'-----------------------------------------------------')
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+'Source code line:')
                self.logger.title(color+'-----------------------------------------------------')
                begin_location = self.source_map.get_location(pc)['begin']
                assert begin_location is not None
                line = begin_location['line'] + 1
                column = begin_location['column'] + 1
                self.logger.title(color+self.source_map.source.filename+':'+str(line)+':'+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+'-----------------------------------------------------')
            self.logger.title(color+'Transaction sequence:')
            self.logger.title(color+'-----------------------------------------------------')
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)
