#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Literal

import logging

# Ethereum VM ('homestead', 'byzantium' or 'petersburg')
EVM_VERSION: Literal['homestead', 'byzantium', 'petersburg'] = 'petersburg'
# Size of population
POPULATION_SIZE: int | None = None
# Number of generations
GENERATIONS: int = 10
# Global timeout in seconds
GLOBAL_TIMEOUT: int | None = None
# Probability of crossover
PROBABILITY_CROSSOVER: float = 0.9
# Probability of mutation
PROBABILITY_MUTATION: float = 0.1
# Maximum number of symbolic execution calls before restting population
MAX_SYMBOLIC_EXECUTION: int = 10
# Solver timeout in milliseconds
SOLVER_TIMEOUT: int = 100
# List of attacker accounts
ATTACKER_ACCOUNTS: list[str] = ['0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef']
# Default gas limit for sending transactions
GAS_LIMIT: int = 450000000
# Default gas price for sending transactions
GAS_PRICE: int = 10
# Default account balance
ACCOUNT_BALANCE: int = 1000000000*(10**18)
# Maximum length of individuals
MAX_INDIVIDUAL_LENGTH: int = 5
# Logging level
LOGGING_LEVEL: int = logging.INFO
# Block height
BLOCK_HEIGHT: int | Literal['latest'] = 'latest'
# RPC Url
RPC_URL: str = 'http://localhost:8545'
# True = Remote fuzzing, False = Local fuzzing
REMOTE_FUZZING: bool = False
# True = Environmental instrumentation enabled, False = Environmental instrumentation disabled
ENVIRONMENTAL_INSTRUMENTATION: bool = True
