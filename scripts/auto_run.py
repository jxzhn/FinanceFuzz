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

if TYPE_CHECKING:
    from multiprocessing.managers import ListProxy, DictProxy
    from multiprocessing.synchronize import Lock

NUM_FUZZING_TIMES = 5
MAX_PROCESS_NUM = 32

FuzzResult = TypedDict('FuzzResult', {
    'contract': NotRequired[str],
    'vulnerabilities': NotRequired[list[str]],
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
    if pragma_match is None:
        fuzz_result.append({
            'error': 'No solidity version pragma statement found'
        })
        print_index_line(pidx, lock, f'({index+1}/{total}) \x1b[31mContract {contract_src} does not have a solidity version pragma statement\x1b[0m')
        return
    pragma_str = pragma_match.group()
    solc_version = solcx.install._select_pragma_version(pragma_str, solcx.get_installed_solc_versions())
    if solc_version is None:
        fuzz_result.append({
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
    
    vulnerabilities: set[str] = set()
    output_file = f'/tmp/fuzz_result_{pidx}.json'
    error = False

    for t in range(NUM_FUZZING_TIMES):
        if os.path.exists(output_file):
            os.remove(output_file)
        
        if os.system(f'PYTHONHASHSEED=1 python {fuzzer_path} -s {os.path.join(base_path, contract_src)} --solc {solc_version} --evm {evm_version} -r {output_file} --seed {t/10 + 0.1} >/dev/null 2>&1') != 0:
            error = True
            break

        with open(output_file, 'r') as fp:
            output = json.load(fp)
        for contract_name, contract_result in output.items():
            for target, error_list in contract_result['advanced_errors'].items():
                vulnerabilities.update([err['type'] for err in error_list])
    
    if error:
        fuzz_result.append({
            'error': 'Fuzzer error (most likely compilation failure)'
        })
        print_index_line(pidx, lock, f'({index+1}/{total}) \x1b[31mContract {contract_src} failed fuzzing\x1b[0m')
        return
            
    fuzz_result.append({
        'contract': contract_src,
        'vulnerabilities': list(vulnerabilities)
    })
    print_index_line(pidx, lock, f'({index+1}/{total}) \x1b[32mContract {contract_src} fuzzing finished\x1b[0m')

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
    pool.join()
    
    with open('./auto_run_result.json', 'w') as fp:
        json.dump(list(fuzz_result), fp, indent=2)

if __name__ == '__main__':
    main()
