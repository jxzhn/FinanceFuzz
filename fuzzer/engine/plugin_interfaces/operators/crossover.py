#!/usr/bin/env python
# -*- coding: utf-8 -*-

''' Module for Genetic Algorithm crossover operator class '''
from __future__ import annotations
from typing import TYPE_CHECKING

from ..metaclasses import CrossoverMeta

if TYPE_CHECKING:
    from ...components.individual import Individual

class Crossover(metaclass=CrossoverMeta):
    '''
    Class for providing an interface to easily extend the behavior of crossover
    operation between two individuals for children breeding.
    '''

    # The probability of crossover (usaully between 0.25 ~ 1.0)
    pc = 0.8

    def cross(self, father: Individual, mother: Individual) -> tuple[Individual, Individual]:
        '''
        Called when we need to cross parents to generate children.

        :param father: The parent individual to be crossed.
        :type father: Individual

        :param mother: The parent individual to be crossed.
        :type mother: Individual

        :return children: Two new children individuals.
        :type children: Tuple of two Individual objects.
        '''
        raise NotImplementedError
