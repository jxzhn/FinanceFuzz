#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING, TypedDict, NotRequired

import os
import sys
import re
import solcx
import solcx.install
from packaging.version import Version
import json
import multiprocessing
import pprint

if TYPE_CHECKING:
    from multiprocessing.managers import ListProxy, DictProxy
    from multiprocessing.synchronize import Lock, Event

MAX_PROCESS_NUM = 20
RESULT_UPDATE_INTERVAL = 30 # (seconds)

FuzzResult = TypedDict('FuzzResult', {
    'contract': NotRequired[str],
    'vulnerabilities': NotRequired[list[str]],
    'result_with_time': NotRequired[list[tuple[str, float]]],
    'error': NotRequired[str]
})

def get_contract_list() -> tuple[str, list[str]]:
    '''
    Get the list of contracts to be fuzzed, return a base path and list of contract paths
    '''
    base_path = '/home/ganjz/FASVERIF-dataset/vulnerability_dataset'
    contract_list: list[str] = []

    for root, _, files in os.walk(base_path):
        for file in files:
            if file.endswith('.sol'):
                contract_list.append(os.path.relpath(os.path.join(root, file), base_path))

    return base_path, contract_list

def pid_index_init(pid_to_index: DictProxy[int, int], lock: Lock) -> None:
    pid = os.getpid()
    with lock:
        pid_to_index[pid] = len(pid_to_index)

def prepare_print_lines(num_lines: int) -> None:
    for _ in range(num_lines):
        print()
    sys.stdout.write(f'\x1b[{num_lines}A\x1b[1000D') # 向上移动光标 num_lines 行，并移到行首
    sys.stdout.flush()

def print_index_line(idx: int, lock: Lock, *args) -> None:
    with lock:
        sys.stdout.write(f'\x1b[{idx+1}B\x1b[1000D\033[K') # 向下移动光标 idx+1 行，并移到行首，并清除该行
        print(*args, end='')
        sys.stdout.write(f'\x1b[{idx+1}A\x1b[1000D') # 向上移动光标 idx+1 行，并移到行首
        sys.stdout.flush()

def fuzz_worker(pid_to_index: DictProxy[int, int], lock: Lock, fuzzer_path: str, base_path: str, contract_src: str, index: int, total: int, fuzz_result: ListProxy[FuzzResult]) -> None:
    pidx = pid_to_index[os.getpid()]

    print_index_line(pidx, lock, f'({index+1}/{total}) Fuzzing contract {contract_src}')
    
    with open(os.path.join(base_path, contract_src), 'r') as fp:
        contract_content = fp.read()
    
    pragma_match = re.search(r'pragma solidity .*;', contract_content)
    no_pragma_version = pragma_match is None
    if no_pragma_version:
        solc_version = Version('0.4.26')
    else:
        pragma_str = pragma_match.group()
        solc_version = solcx.install._select_pragma_version(pragma_str, solcx.get_installed_solc_versions())
        if solc_version is None:
            fuzz_result.append({
                'contract': contract_src,
                'error': 'No suitable solc version found'
            })
            print_index_line(pidx, lock, f'({index+1}/{total}) \x1b[31mCannot find a suitable solc version for contract {contract_src}\x1b[0m')
            return

    if solc_version < Version('0.4.21'):
        evm_version = 'homestead'
    elif solc_version < Version('0.5.5'):
        evm_version = 'byzantium'
    else:
        evm_version = 'petersburg'
    
    output_file = f'/tmp/fuzz_result_{pidx}.json'
    error_code = 0

    if os.path.exists(output_file):
        os.remove(output_file)
        
    error_code = os.system(f'ulimit -v 1000000; python {fuzzer_path} -s {os.path.join(base_path, contract_src)} --solc {solc_version} --evm {evm_version} -r {output_file} >/dev/null 2>&1') >> 8
    if error_code == 255:
        fuzz_result.append({
            'contract': contract_src,
            'error': 'Compilation error with default 0.4.26 solc' if no_pragma_version else 'Compilation error with specified solc version'
        })
        print_index_line(pidx, lock, f'({index+1}/{total}) \x1b[31mContract {contract_src} failed compilation\x1b[0m')
        return
    elif error_code != 0:
        fuzz_result.append({
            'contract': contract_src,
            'error': 'Fuzzer error'
        })
        print_index_line(pidx, lock, f'({index+1}/{total}) \x1b[31mContract {contract_src} failed fuzzing\x1b[0m')
        return
    
    vulnerabilities: set[str] = set()
    result_with_time: list[tuple[str, float]] = []

    with open(output_file, 'r') as fp:
        output = json.load(fp)
    for contract_name, contract_result in output.items():
        for indv_hash, vul_list in contract_result['advanced_errors'].items():
            vulnerabilities.update([vul['type'] for vul in vul_list])
            result_with_time.extend([(vul['type'], vul['time']) for vul in vul_list])
            
    fuzz_result.append({
        'contract': contract_src,
        'vulnerabilities': list(vulnerabilities),
        'result_with_time': sorted(result_with_time, key=lambda x: x[1]),
    })
    print_index_line(pidx, lock, f'({index+1}/{total}) \x1b[32mContract {contract_src} fuzzing finished\x1b[0m')

def result_updater(fuzz_result: ListProxy[FuzzResult], stop_event: Event) -> None:
    while not stop_event.is_set():
        stop_event.wait(timeout=RESULT_UPDATE_INTERVAL)
        with open('./auto_run_result.json', 'w') as fp:
            result_json = pprint.pformat(fuzz_result._getvalue(), compact=True).replace("'",'"').replace('(', '[').replace(')', ']')
            fp.write(result_json)

def main():
    fuzzer_path = os.path.join(os.path.dirname(__file__), '..', 'fuzzer', 'main.py')

    manager = multiprocessing.Manager()

    pid_to_index: DictProxy[int, int] = manager.dict()
    lock = manager.Lock()
    process_pool_size = min(multiprocessing.cpu_count(), MAX_PROCESS_NUM)
    pool = multiprocessing.Pool(process_pool_size, initializer=pid_index_init, initargs=(pid_to_index, lock))

    prepare_print_lines(process_pool_size)

    base_path, contract_list = get_contract_list()
    fuzz_result: ListProxy[FuzzResult] = manager.list()

    for index, contract_src in enumerate(contract_list):
        pool.apply_async(fuzz_worker, (pid_to_index, lock, fuzzer_path, base_path, contract_src, index, len(contract_list), fuzz_result), error_callback=lambda e: print(e))
    pool.close()
    
    stop_event = manager.Event() # Event to stop the result updater
    result_updater_p = multiprocessing.Process(target=result_updater, args=(fuzz_result, stop_event))
    result_updater_p.start()
    
    pool.join()

    stop_event.set()
    result_updater_p.join()

if __name__ == '__main__':
    main()
