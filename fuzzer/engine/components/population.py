#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING, Callable

from engine.components.individual import Individual

if TYPE_CHECKING:
    from engine.components.generator import Generator

class Population:
    def __init__(self, indv_generator: Generator, size: int = 100) -> None:
        '''
        Class for representing population in genetic algorithm.

        :param indv_generator: A individual generator to generate all the individuals
                               in current population.

        :param size: The size of population, number of individuals in population.
        '''
        # Population size.
        if size % 2 != 0:
            raise ValueError('Population size must be an even number')
        self.size = size

        # Generator individual.
        self.indv_generator = indv_generator

        # Population individuals.
        self.individuals: list[Individual] = []

    def init(self, indvs: list[Individual] | None = None) -> Population:
        '''
        Initialize current population with individuals.

        :param indvs: Initial individuals in population, randomly initialized
                      individuals are created if not provided.
        '''

        if indvs is None:
            while len(self.individuals) < self.size:
                indv = Individual(generator=self.indv_generator).init()
                self.individuals.append(indv)
        else:
            # Check individuals.
            if len(indvs) != self.size:
                raise ValueError('Invalid individuals number')
            for indv in indvs:
                if not isinstance(indv, Individual):
                    raise ValueError('individuals must be Individual or a subclass of Individual')
            self.individuals = indvs

        return self

    def __getitem__(self, key: int) -> Individual:
        '''
        Get individual by index.
        '''
        if key < 0 or key >= self.size:
            raise IndexError('Individual index({}) out of range'.format(key))
        return self.individuals[key]

    def __len__(self) -> int:
        '''
        Get length of population.
        '''
        return len(self.individuals)

    def best_indv(self, fitness: Callable[[Individual], float]) -> Individual:
        '''
        The individual with the best fitness.

        '''
        all_fits = self.all_fits(fitness)
        return max(self.individuals, key=lambda indv: all_fits[self.individuals.index(indv)])

    def worst_indv(self, fitness: Callable[[Individual], float]) -> Individual:
        '''
        The individual with the worst fitness.
        '''
        all_fits = self.all_fits(fitness)
        return min(self.individuals, key=lambda indv: all_fits[self.individuals.index(indv)])

    def max(self, fitness: Callable[[Individual], float]) -> float:
        '''
        Get the maximum fitness value in population.
        '''
        return max(self.all_fits(fitness))

    def min(self, fitness: Callable[[Individual], float]) -> float:
        '''
        Get the minimum value of fitness in population.
        '''
        return min(self.all_fits(fitness))

    def mean(self, fitness: Callable[[Individual], float]) -> float:
        '''
        Get the average fitness value in population.
        '''
        all_fits = self.all_fits(fitness)
        return sum(all_fits)/len(all_fits)

    def all_fits(self, fitness: Callable[[Individual], float]) -> list[float]:
        '''
        Get all fitness values in population.
        '''
        return [fitness(indv) for indv in self.individuals]
