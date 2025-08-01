#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING

from .metaclasses import AnalysisMeta

if TYPE_CHECKING:
    from ..engine import EvolutionaryFuzzingEngine
    from ..components.population import Population


class OnTheFlyAnalysis(metaclass=AnalysisMeta):
    '''
    Class for providing an interface to easily extend and customize the behavior
    of the on-the-fly analysis functionality of gapy.
    '''
    # Only used in master process?
    master_only = False

    # Analysis interval.
    interval = 1

    def setup(self, ng: int, engine: EvolutionaryFuzzingEngine) -> None:
        '''
        Function called right before the start of genetic algorithm main iteration
        to allow for custom setup of the analysis object.

        :param ng: The number of generation.
        :type ng: int

        :param engine: The current GAEngine where the analysis is running.
        :type engine: GAEngine
        '''
        raise NotImplementedError

    def register_step(self, g: int, population: Population, engine: EvolutionaryFuzzingEngine) -> None:
        '''
        Function called in each iteration step.

        :param g: Current generation number.
        :type g: int

        :param population: The up to date population of the iteration.
        :type population: Population

        :param engine: The current GAEngine where the analysis is running.
        :type engine: GAEngine
        '''
        raise NotImplementedError

    def finalize(self, population: Population, engine: EvolutionaryFuzzingEngine) -> None:
        '''
        Called after the iteration to allow for custom finalization and
        post-processing of the collected data.

        :param population: The up to date population of the iteration.
        :type population: Population

        :param engine: The current GAEngine where the analysis is running.
        :type engine: GAEngine
        '''
        raise NotImplementedError
