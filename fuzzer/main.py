#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING, Any, cast

import os
import sys
import time
import random
import json
import csv
import solcx
import argparse

from eth_utils.hexadecimal import encode_hex
from eth_utils.address import to_canonical_address
from z3 import Solver
from evm import InstrumentedEVM
from detectors import BasicDetectorExecutor, InvarientDetectorExecutor, EquivalenceDetectorExecutor
from engine import EvolutionaryFuzzingEngine
from engine.components import Generator, Population
from engine.analysis import SymbolicTaintAnalyzer, ExecutionTraceAnalyzer
from engine.environment import FuzzingEnvironment
from engine.operators import LinearRankingSelection
from engine.operators import DataDependencyLinearRankingSelection
from engine.operators import Crossover
from engine.operators import DataDependencyCrossover
from engine.operators import Mutation
from engine.fitness import fitness_function
from utils import settings
from utils.source_map import SourceMap
from utils.utils import initialize_logger, compile, get_interface_from_abi, get_pcs_and_jumpis, get_function_signature_mapping, get_event_signature_mapping, get_contract_types
from utils.control_flow_graph import ControlFlowGraph

if TYPE_CHECKING:
    from eth_typing import HexStr, HexAddress
    from engine.components.individual import InputDict
    from engine.environment import FuzzResult
    from evm.storage_emulation import StateAPIWithFuzzInfo

class Fuzzer:
    def __init__(self, contract_name: str, abi: list, deployment_bytecode: HexStr | None, runtime_bytecode: HexStr, test_instrumented_evm: InstrumentedEVM, blockchain_state: list, solver: Solver, args: argparse.Namespace, seed: float, source_map: SourceMap | None = None):
        global logger

        logger = initialize_logger('Fuzzer  ')
        logger.title('Fuzzing contract %s', contract_name)

        cfg = ControlFlowGraph()
        cfg.build(runtime_bytecode, settings.EVM_VERSION)

        self.contract_name = contract_name
        self.interface = get_interface_from_abi(abi)
        self.deployement_bytecode = deployment_bytecode
        self.blockchain_state = blockchain_state
        self.instrumented_evm = test_instrumented_evm
        self.solver = solver
        self.args = args

        # Get some overall metric on the code
        self.overall_pcs, self.overall_jumpis = get_pcs_and_jumpis(runtime_bytecode)

        # Initialize results
        self.results: FuzzResult = {'errors': {}, 'advanced_errors': {}}

        function_signature_mapping = get_function_signature_mapping(abi)
        event_signature_mapping = get_event_signature_mapping(abi)
        contract_types = get_contract_types({sig for _, sig in function_signature_mapping.items()}, {sig for _, sig in event_signature_mapping.items()})
        logger.info(f'Contract types: {contract_types}')

        # Initialize fuzzing environment
        self.env = FuzzingEnvironment(instrumented_evm=self.instrumented_evm,
                                      contract_name=self.contract_name,
                                      solver=self.solver,
                                      results=self.results,
                                      symbolic_taint_analyzer=SymbolicTaintAnalyzer(),
                                      detector_executor=BasicDetectorExecutor(source_map, function_signature_mapping),
                                      invarient_detector_executor=InvarientDetectorExecutor(contract_types, function_signature_mapping),
                                      equivalence_detector_executor=EquivalenceDetectorExecutor(contract_types, function_signature_mapping),
                                      interface=self.interface,
                                      overall_pcs=self.overall_pcs,
                                      overall_jumpis=self.overall_jumpis,
                                      len_overall_pcs_with_children=0,
                                      other_contracts = list(),
                                      args=args,
                                      seed=seed,
                                      cfg=cfg,
                                      abi=abi)

    def run(self):
        assert self.instrumented_evm.vm is not None
        contract_address = None
        self.instrumented_evm.create_fake_accounts()

        if self.args.source:
            for transaction in self.blockchain_state:
                if transaction['from'].lower() not in self.instrumented_evm.accounts:
                    self.instrumented_evm.accounts.append(self.instrumented_evm.create_fake_account(transaction['from']))

                if not transaction['to']:
                    result = self.instrumented_evm.deploy_contract(transaction['from'], transaction['input'], int(transaction['value']), int(transaction['gas']), int(transaction['gasPrice']))
                    if result.is_error:
                        logger.error('Problem while deploying contract %s using account %s. Error message: %s', self.contract_name, transaction['from'], result._error)
                        sys.exit(-2)
                    else:
                        contract_address = cast('HexAddress', encode_hex(result.msg.storage_address))
                        self.instrumented_evm.accounts.append(contract_address)
                        self.env.nr_of_transactions += 1
                        logger.info('Contract deployed at %s', contract_address)
                        self.env.other_contracts.append(to_canonical_address(contract_address))
                        cc, _ = get_pcs_and_jumpis(self.instrumented_evm.get_code(to_canonical_address(contract_address)).hex())
                        self.env.len_overall_pcs_with_children += len(cc)
                else:
                    input: InputDict = {
                        'transaction': {
                            'from': transaction['from'],
                            'to': transaction['to'],
                            'gaslimit': int(transaction['gas']),
                            'value': int(transaction['value']),
                            'data': transaction['input']
                        },
                        'block': {},
                        'global_state': {},
                        'environment': {}
                    }
                    out = self.instrumented_evm.deploy_transaction(input, int(transaction['gasPrice']), reset_balance=True)

            if 'constructor' in self.interface:
                del self.interface['constructor']

            if not contract_address:
                assert self.deployement_bytecode is not None
                result = self.instrumented_evm.deploy_contract(self.instrumented_evm.accounts[0], self.deployement_bytecode)
                if result.is_error:
                    logger.error('Problem while deploying contract %s using account %s. Error message: %s', self.contract_name, self.instrumented_evm.accounts[0], result._error)
                    sys.exit(-2)
                else:
                    contract_address = cast('HexAddress', encode_hex(result.msg.storage_address))
                    self.instrumented_evm.accounts.append(contract_address)
                    self.env.nr_of_transactions += 1
                    logger.info('Contract deployed at %s', contract_address)

            if contract_address in self.instrumented_evm.accounts:
                self.instrumented_evm.accounts.remove(contract_address)

            self.env.overall_pcs, self.env.overall_jumpis = get_pcs_and_jumpis(self.instrumented_evm.get_code(to_canonical_address(contract_address)).hex())

        if self.args.abi:
            if 'constructor' in self.interface:
                del self.interface['constructor']
            
            contract_address = self.args.contract
        
        assert contract_address is not None

        if not settings.ENVIRONMENTAL_INSTRUMENTATION:
            # compile and deploy helper contracts
            for helper_src in settings.HELPER_CONTRACTS:
                helper_src = os.path.join(os.path.dirname(__file__), 'helper_contracts', helper_src)
                compiler_output = compile(settings.HELPER_COMPILER_VERSION, settings.EVM_VERSION, helper_src)
                if not compiler_output:
                    logger.error('No compiler output for: ' + helper_src)
                    sys.exit(-1)
                for contract_name, contract in compiler_output['contracts'][helper_src].items():
                    if contract['abi'] and contract['evm']['bytecode']['object'] and contract['evm']['deployedBytecode']['object']:
                        result = self.instrumented_evm.deploy_contract(self.instrumented_evm.accounts[0], contract['evm']['bytecode']['object'])
                        if result.is_error:
                            logger.error('Problem while deploying contract %s using account %s. Error message: %s', contract_name, self.instrumented_evm.accounts[0], result._error)
                            sys.exit(-2)
                        else:
                            helper_address = cast('HexAddress', encode_hex(result.msg.storage_address))
                            self.instrumented_evm.accounts.append(helper_address)
                            self.env.nr_of_transactions += 1
                            logger.info('Helper contract %s deployed at %s', contract_name, helper_address)
                            if contract_name == 'ReentrancyAttacker':
                                state = cast('StateAPIWithFuzzInfo', self.instrumented_evm.vm.state)
                                state.reentrancy_helper = helper_address

        self.instrumented_evm.create_snapshot()

        generator = Generator(interface=self.interface,
                              bytecode=self.deployement_bytecode,
                              accounts=self.instrumented_evm.accounts,
                              contract=contract_address)

        if self.args.history_seed:
            with open(self.args.history_seed) as csv_file:
                csv_reader = csv.DictReader(csv_file)
                history_transactions = list(csv_reader)
            generator.init_pool_from_history(history_transactions)

        # Create initial population
        size = max(2 * len(self.interface), 100)
        population = Population(indv_generator=generator,
                                size=settings.POPULATION_SIZE if settings.POPULATION_SIZE else size).init()

        # Create genetic operators
        if self.args.data_dependency:
            selection = DataDependencyLinearRankingSelection(env=self.env)
            crossover = DataDependencyCrossover(pc=settings.PROBABILITY_CROSSOVER, env=self.env)
            mutation = Mutation(pm=settings.PROBABILITY_MUTATION)
        else:
            selection = LinearRankingSelection()
            crossover = Crossover(pc=settings.PROBABILITY_CROSSOVER)
            mutation = Mutation(pm=settings.PROBABILITY_MUTATION)

        # Create and run our evolutionary fuzzing engine
        engine = EvolutionaryFuzzingEngine(population=population, selection=selection, crossover=crossover, mutation=mutation, mapping=get_function_signature_mapping(self.env.abi))
        engine.fitness_register(lambda x: fitness_function(x, self.env))
        engine.analysis.append(ExecutionTraceAnalyzer(self.env))

        self.env.execution_begin = time.time()
        self.env.population = population

        engine.run(ng=settings.GENERATIONS)

        if self.env.args.cfg:
            if self.env.args.source:
                self.env.cfg.save_control_flow_graph(os.path.splitext(self.env.args.source)[0]+'-'+self.contract_name, 'pdf')
            elif self.env.args.abi:
                self.env.cfg.save_control_flow_graph(os.path.join(os.path.dirname(self.env.args.abi[0]), self.contract_name), 'pdf')

        self.instrumented_evm.reset()

def main():
    print_logo()
    args = launch_argument_parser()

    logger = initialize_logger('Main    ')

    # Check if contract has already been analyzed
    if args.results and os.path.exists(args.results):
        # os.remove(args.results)
        logger.info('Contract '+str(args.source)+' has already been analyzed: '+str(args.results))
        sys.exit(0)

    # Initializing random
    if args.seed:
        seed = args.seed
        if not 'PYTHONHASHSEED' in os.environ:
            logger.info('Please set PYTHONHASHSEED to \'1\' for Python\'s hash function to behave deterministically.')
    else:
        seed = random.random()
    random.seed(seed)
    logger.title('Initializing seed to %s', seed)

    # Initialize EVM
    instrumented_evm = InstrumentedEVM(settings.RPC_URL)
    instrumented_evm.set_vm_by_name(settings.EVM_VERSION)

    # Create Z3 solver instance
    solver = Solver()
    solver.set('timeout', settings.SOLVER_TIMEOUT)

    # Parse blockchain state if provided
    blockchain_state = []
    if args.blockchain_state:
        if args.blockchain_state.endswith('.json'):
            with open(args.blockchain_state) as json_file:
                for line in json_file.readlines():
                    blockchain_state.append(json.loads(line))
        elif args.blockchain_state.isnumeric():
            settings.BLOCK_HEIGHT = int(args.blockchain_state)
            instrumented_evm.set_vm(settings.BLOCK_HEIGHT)
        else:
            logger.error('Unsupported input file: ' + args.blockchain_state)
            sys.exit(-1)

    # Compile source code to get deployment bytecode, runtime bytecode and ABI
    if args.source:
        if args.source.endswith('.sol'):
            compiler_output = compile(args.solc_version, settings.EVM_VERSION, args.source)
            if not compiler_output:
                logger.error('No compiler output for: ' + args.source)
                sys.exit(-1)
            for contract_name, contract in compiler_output['contracts'][args.source].items():
                if args.contract and contract_name != args.contract:
                    continue
                if contract['abi'] and contract['evm']['bytecode']['object'] and contract['evm']['deployedBytecode']['object']:
                    source_map = SourceMap(':'.join([args.source, contract_name]), compiler_output)
                    Fuzzer(contract_name, contract['abi'], contract['evm']['bytecode']['object'], contract['evm']['deployedBytecode']['object'], instrumented_evm, blockchain_state, solver, args, seed, source_map).run()
        else:
            logger.error('Unsupported input file: ' + args.source)
            sys.exit(-1)

    if args.abi:
        abi = []
        for abi_file in args.abi:
            with open(abi_file) as json_file:
                abi += json.load(json_file)
        runtime_bytecode = cast('HexStr', instrumented_evm.get_code(to_canonical_address(args.contract)).hex())
        Fuzzer(args.contract, abi, None, runtime_bytecode, instrumented_evm, blockchain_state, solver, args, seed).run()

def launch_argument_parser() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    # Contract parameters
    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument('-s', '--source', type=str,
                        help='Solidity smart contract source code file (.sol).')
    group1.add_argument('-a', '--abi', type=str, nargs='*',
                        help='Smart contract ABI file (.json), supports automatic merging of multiple files.')

    #group2 = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument('-c', '--contract', type=str,
                        help='Contract name to be fuzzed (if Solidity source code file provided) or blockchain contract address (if ABI file provided).')

    parser.add_argument('-b', '--blockchain-state', type=str,
                        help='Initialize fuzzer with a blockchain state by providing a JSON file (if Solidity source code file provided) or a block number (if ABI file provided).')

    # Compiler parameters
    parser.add_argument('--solc', help='Solidity compiler version (default \'' + str(
        solcx.get_solc_version()) + '\'). Installed compiler versions: ' + str(solcx.get_installed_solc_versions()) + '.',
                        action='store', dest='solc_version', type=str)
    parser.add_argument('--evm', help='Ethereum VM (default \'' + str(
        settings.EVM_VERSION) + '\'). Available VM\'s: \'homestead\', \'byzantium\' or \'petersburg\'.', action='store',
                        dest='evm_version', type=str)

    # Evolutionary parameters
    group3 = parser.add_mutually_exclusive_group(required=False)
    group3.add_argument('-g', '--generations',
                        help='Number of generations (default ' + str(settings.GENERATIONS) + ').', action='store',
                        dest='generations', type=int)
    group3.add_argument('-t', '--timeout',
                        help='Number of seconds for fuzzer to stop.', action='store',
                        dest='global_timeout', type=int)
    parser.add_argument('-n', '--population-size',
                        help='Size of the population.', action='store',
                        dest='population_size', type=int)
    parser.add_argument('-pc', '--probability-crossover',
                        help='Size of the population.', action='store',
                        dest='probability_crossover', type=float)
    parser.add_argument('-pm', '--probability-mutation',
                        help='Size of the population.', action='store',
                        dest='probability_mutation', type=float)

    # Miscellaneous parameters
    parser.add_argument('-r', '--results', type=str, help='Folder or JSON file where results should be stored.')
    parser.add_argument('--seed', type=float, help='Initialize the random number generator with a given seed.')
    parser.add_argument('--cfg', help='Build control-flow graph and highlight code coverage.', action='store_true')
    parser.add_argument('--rpc-url', help='Ethereum RPC service provider url.', action='store', dest='rpc_url', type=str)

    parser.add_argument('--history-seed', help='Initialize fuzzing pool with seed arguments from history file (.csv).', dest='history_seed', type=str)

    parser.add_argument('--data-dependency',
                        help='Disable/Enable data dependency analysis: 0 - Disable, 1 - Enable (default: 1)', action='store',
                        dest='data_dependency', type=int)
    parser.add_argument('--constraint-solving',
                        help='Disable/Enable constraint solving: 0 - Disable, 1 - Enable (default: 1)', action='store',
                        dest='constraint_solving', type=int)
    parser.add_argument('--environmental-instrumentation',
                        help='Disable/Enable environmental instrumentation: 0 - Disable, 1 - Enable (default: 0)', action='store',
                        dest='environmental_instrumentation', type=int)
    parser.add_argument('--max-individual-length',
                        help='Maximal length of an individual (default: ' + str(settings.MAX_INDIVIDUAL_LENGTH) + ')', action='store',
                        dest='max_individual_length', type=int)
    parser.add_argument('--max-symbolic-execution',
                        help='Maximum number of symbolic execution calls before restting population (default: ' + str(settings.MAX_SYMBOLIC_EXECUTION) + ')', action='store',
                        dest='max_symbolic_execution', type=int)

    version = 'ConFuzzius - Version 0.0.2 - '
    version += '\'By three methods we may learn wisdom:\n'
    version += 'First, by reflection, which is noblest;\n'
    version += 'Second, by imitation, which is easiest;\n'
    version += 'And third by experience, which is the bitterest.\'\n'
    parser.add_argument('-v', '--version', action='version', version=version)

    args = parser.parse_args()

    if not args.contract:
        args.contract = ''

    if args.source and args.contract.startswith('0x'):
        parser.error('--source requires --contract to be a name, not an address.')
    if args.source and args.blockchain_state and args.blockchain_state.isnumeric():
        parser.error('--source requires --blockchain-state to be a file, not a number.')

    if args.abi and not args.contract.startswith('0x'):
        parser.error('--abi requires --contract to be an address, not a name.')
    if args.abi and args.blockchain_state and not args.blockchain_state.isnumeric():
        parser.error('--abi requires --blockchain-state to be a number, not a file.')

    if args.evm_version:
        settings.EVM_VERSION = args.evm_version
    if not args.solc_version:
        args.solc_version = solcx.get_solc_version()
    if args.generations:
        settings.GENERATIONS = args.generations
    if args.global_timeout:
        settings.GLOBAL_TIMEOUT = args.global_timeout
    if args.population_size:
        settings.POPULATION_SIZE = args.population_size
    if args.probability_crossover:
        settings.PROBABILITY_CROSSOVER = args.probability_crossover
    if args.probability_mutation:
        settings.PROBABILITY_MUTATION = args.probability_mutation

    if args.data_dependency == None:
        args.data_dependency = 1
    if args.constraint_solving == None:
        args.constraint_solving = 1
    if args.environmental_instrumentation == None:
        args.environmental_instrumentation = 0

    if args.environmental_instrumentation == 1:
        settings.ENVIRONMENTAL_INSTRUMENTATION = True
    elif args.environmental_instrumentation == 0:
        settings.ENVIRONMENTAL_INSTRUMENTATION = False

    if args.max_individual_length:
        settings.MAX_INDIVIDUAL_LENGTH = args.max_individual_length
    if args.max_symbolic_execution:
        settings.MAX_SYMBOLIC_EXECUTION = args.max_symbolic_execution

    if args.abi:
        settings.REMOTE_FUZZING = True

    if args.rpc_url:
        settings.RPC_URL = args.rpc_url

    return args

def print_logo():
    print(r'                   ________                              ')
    print(r'_______ ________  ____  __/___  _________________________')
    print(r'__  __ `__ \_  / / /_  /_ _  / / /__  /__  /_  _ \_  ___/')
    print(r'_  / / / / /  /_/ /_  __/ / /_/ /__  /__  /_/  __/  /    ')
    print(r'/_/ /_/ /_/_\__, / /_/    \__,_/ _____/____/\___//_/     ')
    print(r'           /____/                                        ')

if '__main__' == __name__:
    main()
