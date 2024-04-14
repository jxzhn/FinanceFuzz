from __future__ import annotations
from typing import TYPE_CHECKING, Literal
from abc import ABCMeta, abstractmethod

if TYPE_CHECKING:
    from engine.environment import FuzzingEnvironment
    from engine.components.individual import InputDict
    from evm.storage_emulation import ComputationAPIWithFuzzInfo

class BaseEquivalenceDetector(metaclass=ABCMeta):
    severity: Literal['Low', 'Medium', 'High']
    type: str
    error_msg: str
    is_enable: bool
    
    @abstractmethod
    def run_flavored_transaction(self, tx_input: InputDict, tx_output: ComputationAPIWithFuzzInfo, transaction_index: int, env: FuzzingEnvironment) -> bool:
        ...

    @abstractmethod
    def final(self, env: FuzzingEnvironment) -> bool:
        ...