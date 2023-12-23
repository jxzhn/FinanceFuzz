#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING, TypedDict, Any, NotRequired, cast

import sys
import random

from copy import deepcopy, copy
from eth_abi.abi import encode

from utils.utils import initialize_logger

if TYPE_CHECKING:
    from eth_typing import HexStr, HexAddress
    from engine.components.generator import Generator, FuzzTransactionInput

TransactionDict = TypedDict('TransactionDict', {
    'from': 'HexAddress',
    'to': 'HexAddress',
    'value': int,
    'gaslimit': int,
    'data': 'HexStr'
})

BlockDict = TypedDict('BlockDict', {
    'timestamp': NotRequired[int],
    'blocknumber': NotRequired[int]
})

GlobalStateDict = TypedDict('GlobalStateDict', {
    'balance': NotRequired[int],
    'call_return': NotRequired[dict['HexAddress', Any]],
    'extcodesize': NotRequired[dict['HexAddress', int]]
})

EnvironmentDict = TypedDict('EnvironmentDict', {
    'returndatasize': NotRequired[dict['HexAddress', int]]
})

InputDict = TypedDict('InputDict', {
    'transaction': TransactionDict,
    'block': BlockDict,
    'global_state': GlobalStateDict,
    'environment': EnvironmentDict
})

class Individual:
    def __init__(self, generator: Generator) -> None:
        self.logger = initialize_logger('Individual')
        self.chromosome: list[FuzzTransactionInput] = []
        self.solution: list[InputDict] = []
        self.generator = generator

    @property
    def hash(self) -> str:
        if not self.solution:
            self.solution = self.decode()
        return str(hash(str([tx for tx in self.solution])))

    def init(self, chromosome: list[FuzzTransactionInput] | None = None) -> Individual:
        if not chromosome:
            self.chromosome = self.generator.generate_random_individual()
        else:
            self.chromosome = chromosome
        self.solution = self.decode()
        return self

    def clone(self) -> Individual:
        indv = self.__class__(generator=self.generator)
        indv.init(chromosome=deepcopy(self.chromosome))
        return indv

    def decode(self) -> list[InputDict]:
        solution: list[InputDict] = []

        for i in range(len(self.chromosome)):
            fuzz_input_data = self.chromosome[i]

            transaction: TransactionDict = {
                'from': copy(fuzz_input_data['account']),
                'to': copy(fuzz_input_data['contract']),
                'value': copy(fuzz_input_data['amount']),
                'gaslimit': copy(fuzz_input_data['gaslimit']),
                'data': self.get_transaction_data_from_chromosome(i)
            }

            block: BlockDict = {}
            if 'timestamp' in fuzz_input_data and fuzz_input_data['timestamp'] is not None:
                block['timestamp'] = copy(fuzz_input_data['timestamp'])
            if 'blocknumber' in fuzz_input_data and fuzz_input_data['blocknumber'] is not None:
                block['blocknumber'] = copy(fuzz_input_data['blocknumber'])

            global_state: GlobalStateDict = {}
            if 'balance' in fuzz_input_data and fuzz_input_data['balance'] is not None:
                global_state['balance'] = copy(fuzz_input_data['balance'])
            if 'call_return' in fuzz_input_data and fuzz_input_data['call_return'] is not None\
                    and len(fuzz_input_data['call_return']) > 0:
                global_state['call_return'] = copy(fuzz_input_data['call_return'])
            if 'extcodesize' in fuzz_input_data and fuzz_input_data['extcodesize'] is not None\
                    and len(fuzz_input_data['extcodesize']) > 0:
                global_state['extcodesize'] = copy(fuzz_input_data['extcodesize'])

            environment: EnvironmentDict = {}
            if 'returndatasize' in fuzz_input_data and fuzz_input_data['returndatasize'] is not None:
                environment['returndatasize'] = copy(fuzz_input_data['returndatasize'])

            input: InputDict = {'transaction':transaction, 'block' : block, 'global_state' : global_state, 'environment': environment}
            solution.append(input)
        
        return solution

    def get_transaction_data_from_chromosome(self, chromosome_index: int) -> HexStr:
        data = ''
        arguments: list[Any] = []
        function = ''
        for j in range(len(self.chromosome[chromosome_index]['arguments'])):
            if self.chromosome[chromosome_index]['arguments'][j] == 'fallback':
                function = 'fallback'
                data += random.choice(['', '00000000'])
            elif self.chromosome[chromosome_index]['arguments'][j] == 'constructor':
                function = 'constructor'
                data += cast(str, self.generator.bytecode)
            elif not isinstance(self.chromosome[chromosome_index]['arguments'][j], bytearray) and \
                    not isinstance(self.chromosome[chromosome_index]['arguments'][j], list) and \
                    self.chromosome[chromosome_index]['arguments'][j] in self.generator.interface:
                function = self.chromosome[chromosome_index]['arguments'][j]
                data += self.chromosome[chromosome_index]['arguments'][j]
            else:
                arguments.append(self.chromosome[chromosome_index]['arguments'][j])
        try:
            argument_types = [argument_type.replace(' storage', '').replace(' memory', '') for argument_type in self.generator.interface[function]]
            data += encode(argument_types, arguments).hex()
        except Exception as e:
            self.logger.error('%s', e)
            self.logger.error('%s: %s -> %s', function, self.generator.interface[function], arguments)
            sys.exit(-6)
        return cast('HexStr', data)
