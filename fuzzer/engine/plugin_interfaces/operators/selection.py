#!/usr/bin/env python
# -*- coding: utf-8 -*-

''' Module for Genetic Algorithm selection operator class '''
from __future__ import annotations
from typing import TYPE_CHECKING, Callable

from ..metaclasses import SelectionMeta

if TYPE_CHECKING:
    from ...components.individual import Individual
    from ...components.population import Population

class Selection(metaclass=SelectionMeta):
    '''
    Class for providing an interface to easily extend the behavior of selection
    operation.
    '''

    def select(self, population: Population, fitness: Callable[[Individual], float]) -> tuple[Individual, Individual]:
        '''
        Called when we need to select parents from a population to later breeding.

        :param population: The current population.
        :type population: Population

        :return parents: Two selected individuals for crossover.
        :type parents: Tuple of two Individual objects.
        '''
        raise NotImplementedError
