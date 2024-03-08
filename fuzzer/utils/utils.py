#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Any

import os
import re
import shlex
import solcx
import logging
import subprocess

from web3 import Web3
from .settings import LOGGING_LEVEL
from packaging.version import Version
from eth_typing import HexAddress

from eth_utils.conversions import to_bytes
from eth_utils.address import to_normalized_address

class MyLogger:
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    @staticmethod
    def bold(x: Any):
        return ''.join(['\033[1m', x, '\033[0m']) if isinstance(x, str) else x

    @staticmethod
    def red(x: Any):
        return ''.join(['\033[91m', x, '\033[0m']) if isinstance(x, str) else x
    
    def title(self, *a: Any):
        self.logger.info(*[self.bold(x) for x in a])
    
    def error(self, *a: Any):
        self.logger.error(*[self.red(self.bold(x)) for x in a])
    
    def warning(self, *a: Any):
        self.logger.warning(*[self.red(self.bold(x)) for x in a])
    
    def info(self, *a: Any):
        self.logger.info(*a)
    
    def debug(self, *a: Any):
        self.logger.debug(*a)

def initialize_logger(name: str) -> MyLogger:
    logger = logging.getLogger(name)
    logger.setLevel(level=LOGGING_LEVEL)
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    return MyLogger(logger)

def code_bool(value: bool) -> str:
    return str(int(value)).zfill(64)

def code_uint(value: int) -> str:
    return hex(value).replace('0x', '').zfill(64)

def code_int(value: int) -> str:
    return hex(value).replace('0x', '').zfill(64)

def code_address(value: str) -> str:
    return value.zfill(64)

def code_bytes(value: str) -> str:
    return value.ljust(64, '0')

def code_type(value: Any, type: str) -> str:
    if type == 'bool':
        return code_bool(value)
    elif type.startswith('uint'):
        return code_uint(value)
    elif type.startswith('int'):
        return code_int(value)
    elif type == 'address':
        return code_address(value)
    elif type.startswith('bytes'):
        return code_bytes(value)
    else:
        raise Exception()

def run_command(cmd: str) -> bytes:
    FNULL = open(os.devnull, 'w')
    p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=FNULL)
    return p.communicate()[0]

def compile(solc_version: str | Version, evm_version: str, source_code_file: str) -> dict | None:
    if isinstance(solc_version, str):
        solc_version = Version(solc_version)
    out = None
    source_code = ''
    with open(source_code_file, 'r') as file:
        source_code = file.read()
    try:
        if not solc_version in solcx.get_installed_solc_versions():
            solcx.install_solc(solc_version)
        solcx.set_solc_version(solc_version, True)
        out = solcx.compile_standard({
            'language': 'Solidity',
            'sources': {source_code_file: {'content': source_code}},
            'settings': {
                'optimizer': {
                    'enabled': True,
                    'runs': 200
                },
                'evmVersion': evm_version,
                'outputSelection': {
                    source_code_file: {
                        '*':
                            [
                                'abi',
                                'evm.deployedBytecode',
                                'evm.bytecode.object',
                                'evm.legacyAssembly',
                            ],
                    }
                }
            }
        }, allow_paths='.')
    except Exception as e:
        print('Error: Solidity compilation failed!')
        print(e.message) # type: ignore
    return out

def get_interface_from_abi(abi: list) -> dict[str, list[str]]:
    '''
    return a dict mapping function signature to its argument type list
    '''
    interface: dict[str, list[str]] = {}
    for field in abi:
        if field['type'] == 'function':
            function_name = field['name']
            function_inputs = []
            signature = function_name + '('
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                function_inputs.append(input_type)
                signature += input_type
                if i < len(field['inputs']) - 1:
                    signature += ','
            signature += ')'
            hash = Web3.keccak(text=signature)[0:4].hex()
            interface[hash] = function_inputs
        elif field['type'] == 'constructor':
            function_inputs = []
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                function_inputs.append(input_type)
            interface['constructor'] = function_inputs
    if not 'fallback' in interface:
        interface['fallback'] = []
    return interface

def get_function_signature_mapping(abi: list) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for field in abi:
        if field['type'] == 'function':
            function_name = field['name']
            signature = function_name + '('
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                signature += input_type
                if i < len(field['inputs']) - 1:
                    signature += ','
            signature += ')'
            hash = Web3.keccak(text=signature)[0:4].hex()
            mapping[hash] = signature
    if not 'fallback' in mapping:
        mapping['fallback'] = 'fallback'
    return mapping

def get_event_signature_mapping(abi: list) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for field in abi:
        if field['type'] == 'event':
            function_name = field['name']
            signature = function_name + '('
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                signature += input_type
                if i < len(field['inputs']) - 1:
                    signature += ','
            signature += ')'
            hash = Web3.keccak(text=signature)[0:4].hex()
            mapping[hash] = signature
    return mapping

def remove_swarm_hash(bytecode: str) -> str:
    if isinstance(bytecode, str):
        if bytecode.endswith('0029'):
            bytecode = re.sub(r'a165627a7a72305820\S{64}0029$', '', bytecode)
        if bytecode.endswith('0033'):
            bytecode = re.sub(r'5056fe.*?0033$', '5056', bytecode)
    return bytecode

def get_pcs_and_jumpis(bytecode: str) -> tuple[list[int], list[int]]:
    _bytecode = bytes.fromhex(remove_swarm_hash(bytecode).replace('0x', ''))
    i = 0
    pcs = []
    jumpis = []
    while i < len(_bytecode):
        opcode = _bytecode[i]
        pcs.append(i)
        if opcode == 87: # JUMPI
            jumpis.append(hex(i))
        if opcode >= 96 and opcode <= 127: # PUSH
            size = opcode - 96 + 1
            i += size
        i += 1
    if len(pcs) == 0:
        pcs = [0]
    return (pcs, jumpis)

def convert_stack_value_to_int(stack_value: tuple) -> int:
    if stack_value[0] == int:
        return stack_value[1]
    elif stack_value[0] == bytes:
        return int.from_bytes(stack_value[1], 'big')
    else:
        raise Exception('Error: Cannot convert stack value to int. Unknown type: ' + str(stack_value[0]))

def convert_stack_value_to_hex(stack_value: tuple) -> str:
    if stack_value[0] == int:
        return hex(stack_value[1]).replace('0x', '').zfill(64)
    elif stack_value[0] == bytes:
        return stack_value[1].hex().zfill(64)
    else:
        raise Exception('Error: Cannot convert stack value to hex. Unknown type: ' + str(stack_value[0]))

def is_fixed(value: Any) -> bool:
    return isinstance(value, int)

def split_len(seq: list, length: int) -> list[list]:
    return [seq[i:i + length] for i in range(0, len(seq), length)]

def print_individual_solution_as_transaction(logger: MyLogger, individual_solution: list, color: str = '', function_signature_mapping: dict = {}, transaction_index: int | None = None):
    for index, input in enumerate(individual_solution):
        transaction = input['transaction']
        if not transaction['to'] == None:
            if transaction['data'].startswith('0x'):
                hash = transaction['data'][0:10]
            else:
                hash = transaction['data'][0:8]
            if len(individual_solution) == 1 or (transaction_index is not None and transaction_index == 0):
                if hash in function_signature_mapping:
                    logger.title(color+'Transaction - ' + function_signature_mapping[hash] + ':')
                else:
                    logger.title(color+'Transaction:')
            else:
                if hash in function_signature_mapping:
                    logger.title(color+'Transaction ' + str(index + 1) + ' - ' + function_signature_mapping[hash] + ':')
                else:
                    logger.title(color+'Transaction ' + str(index + 1) + ':')
            logger.title(color+'-----------------------------------------------------')
            logger.title(color+'From:      ' + transaction['from'])
            logger.title(color+'To:        ' + str(transaction['to']))
            logger.title(color+'Value:     ' + str(transaction['value']) + ' Wei')
            logger.title(color+'Gas Limit: ' + str(transaction['gaslimit']))
            i = 0
            for data in split_len('0x' + transaction['data'].replace('0x', ''), 42):
                if i == 0:
                    logger.title(color+'Input:     ' + str(data))
                else:
                    logger.title(color+'           ' + str(data))
                i += 1
            logger.title(color+'-----------------------------------------------------')
            if transaction_index is not None and index + 1 > transaction_index:
                break

def normalize_32_byte_hex_address(value: str) -> HexAddress:
    as_bytes = to_bytes(hexstr=value)
    return to_normalized_address(as_bytes[-20:])
