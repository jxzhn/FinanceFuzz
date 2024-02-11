from typing import Literal
from abc import ABCMeta

class BaseBasicDetector(metaclass=ABCMeta):
    swc_id: int
    severity: Literal['Low', 'Medium', 'High']
