from __future__ import annotations
from typing import TYPE_CHECKING, Literal
from abc import ABCMeta, abstractmethod

if TYPE_CHECKING:
    from engine.environment import FuzzingEnvironment
    from engine.components.individual import InputDict
    from evm.storage_emulation import ComputationAPIWithFuzzInfo

class BaseInvarientDetector(metaclass=ABCMeta):
    severity: Literal['Low', 'Medium', 'High']

    @abstractmethod
    def prepare_detect_step(self, env: FuzzingEnvironment) -> None:
        ...
    
    @abstractmethod
    def run_detect_step(self, test: InputDict, result: ComputationAPIWithFuzzInfo, env: FuzzingEnvironment) -> tuple[str, str] | tuple[None, None]:
        ...