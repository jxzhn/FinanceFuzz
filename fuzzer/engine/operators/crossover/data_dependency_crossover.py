#!/usr/bin/env python3
# -*- coding: utf-8 -*-

''' Crossover operator implementation. '''
from __future__ import annotations
from typing import TYPE_CHECKING

import random

from utils import settings

from ...plugin_interfaces.operators.crossover import Crossover
from ...components.individual import Individual

if TYPE_CHECKING:
    from ...environment import FuzzingEnvironment

class DataDependencyCrossover(Crossover):
    def __init__(self, pc: float, env: FuzzingEnvironment) -> None:
        '''
        :param pc: The probability of crossover (usaully between 0.25 ~ 1.0)
        :type pc: float in (0.0, 1.0]
        '''
        if pc <= 0.0 or pc > 1.0:
            raise ValueError('Invalid crossover probability')

        self.pc = pc
        self.env = env

    def cross(self, father: Individual, mother: Individual) -> tuple[Individual, Individual]:
        '''
        Cross the selected individuals.
        '''

        do_cross = True if random.random() <= self.pc else False

        if mother is None:
            return father.clone(), father.clone()

        _father = father.clone()
        _mother = mother.clone()

        if not do_cross or len(father.chromosome) + len(mother.chromosome) > settings.MAX_INDIVIDUAL_LENGTH:
            return _father, _mother

        #f_a = set([i['arguments'][0] for i in _father.chromosome])
        #m_a = set([i['arguments'][0] for i in _mother.chromosome])
        #if not f_a.isdisjoint(m_a):
        #    if len(f_a.difference(m_a)) == 0 or len(m_a.difference(f_a)) == 0:
        #        return _father, _mother

        father_reads, father_writes = DataDependencyCrossover.extract_reads_and_writes(_father, self.env)
        mother_reads, mother_writes = DataDependencyCrossover.extract_reads_and_writes(_mother, self.env)

        if not mother_reads.isdisjoint(father_writes):
            child1 = Individual(generator=_father.generator)
            child1.init(chromosome=_father.chromosome + _mother.chromosome)
        else:
            child1 = _father

        if not father_reads.isdisjoint(mother_writes):
            child2 = Individual(generator=_mother.generator)
            child2.init(chromosome=_mother.chromosome + _father.chromosome)
        else:
            child2 = _mother

        return child1, child2

    @staticmethod
    def extract_reads_and_writes(individual: Individual, env: FuzzingEnvironment) -> tuple[set[int], set[int]]:
        reads: set[int] = set()
        writes: set[int] = set()

        for t in individual.chromosome:
            _function_hash = t['arguments'][0]
            if _function_hash in env.data_dependencies:
                reads.update(env.data_dependencies[_function_hash]['read'])
                writes.update(env.data_dependencies[_function_hash]['write'])

        return reads, writes
