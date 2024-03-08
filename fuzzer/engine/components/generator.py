#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING, Iterable, Any, TypedDict, NotRequired, cast

import random
import collections

from utils import settings
from utils.utils import *
from eth_abi.abi import decode

if TYPE_CHECKING:
    from eth_typing import HexStr, HexAddress

UINT_MAX = {
    1: int('0xff', 16),
    2: int('0xffff', 16),
    3: int('0xffffff', 16),
    4: int('0xffffffff', 16),
    5: int('0xffffffffff', 16),
    6: int('0xffffffffffff', 16),
    7: int('0xffffffffffffff', 16),
    8: int('0xffffffffffffffff', 16),
    9: int('0xffffffffffffffffff', 16),
    10: int('0xffffffffffffffffffff', 16),
    11: int('0xffffffffffffffffffffff', 16),
    12: int('0xffffffffffffffffffffffff', 16),
    13: int('0xffffffffffffffffffffffffff', 16),
    14: int('0xffffffffffffffffffffffffffff', 16),
    15: int('0xffffffffffffffffffffffffffffff', 16),
    16: int('0xffffffffffffffffffffffffffffffff', 16),
    17: int('0xffffffffffffffffffffffffffffffffff', 16),
    18: int('0xffffffffffffffffffffffffffffffffffff', 16),
    19: int('0xffffffffffffffffffffffffffffffffffffff', 16),
    20: int('0xffffffffffffffffffffffffffffffffffffffff', 16),
    21: int('0xffffffffffffffffffffffffffffffffffffffffff', 16),
    22: int('0xffffffffffffffffffffffffffffffffffffffffffff', 16),
    23: int('0xffffffffffffffffffffffffffffffffffffffffffffff', 16),
    24: int('0xffffffffffffffffffffffffffffffffffffffffffffffff', 16),
    25: int('0xffffffffffffffffffffffffffffffffffffffffffffffffff', 16),
    26: int('0xffffffffffffffffffffffffffffffffffffffffffffffffffff', 16),
    27: int('0xffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16),
    28: int('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16),
    29: int('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16),
    30: int('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16),
    31: int('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16),
    32: int('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16)
}

INT_MAX = {
    1: int('0x7f', 16),
    2: int('0x7fff', 16),
    3: int('0x7fffff', 16),
    4: int('0x7fffffff', 16),
    5: int('0x7fffffffff', 16),
    6: int('0x7fffffffffff', 16),
    7: int('0x7fffffffffffff', 16),
    8: int('0x7fffffffffffffff', 16),
    9: int('0x7fffffffffffffffff', 16),
    10: int('0x7fffffffffffffffffff', 16),
    11: int('0x7fffffffffffffffffffff', 16),
    12: int('0x7fffffffffffffffffffffff', 16),
    13: int('0x7fffffffffffffffffffffffff', 16),
    14: int('0x7fffffffffffffffffffffffffff', 16),
    15: int('0x7fffffffffffffffffffffffffffff', 16),
    16: int('0x7fffffffffffffffffffffffffffffff', 16),
    17: int('0x7fffffffffffffffffffffffffffffffff', 16),
    18: int('0x7fffffffffffffffffffffffffffffffffff', 16),
    19: int('0x7fffffffffffffffffffffffffffffffffffff', 16),
    20: int('0x7fffffffffffffffffffffffffffffffffffffff', 16),
    21: int('0x7fffffffffffffffffffffffffffffffffffffffff', 16),
    22: int('0x7fffffffffffffffffffffffffffffffffffffffffff', 16),
    23: int('0x7fffffffffffffffffffffffffffffffffffffffffffff', 16),
    24: int('0x7fffffffffffffffffffffffffffffffffffffffffffffff', 16),
    25: int('0x7fffffffffffffffffffffffffffffffffffffffffffffffff', 16),
    26: int('0x7fffffffffffffffffffffffffffffffffffffffffffffffffff', 16),
    27: int('0x7fffffffffffffffffffffffffffffffffffffffffffffffffffff', 16),
    28: int('0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16),
    29: int('0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16),
    30: int('0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16),
    31: int('0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16),
    32: int('0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16)
}

INT_MIN = {
    1: int('-0x80', 16),
    2: int('-0x8000', 16),
    3: int('-0x800000', 16),
    4: int('-0x80000000', 16),
    5: int('-0x8000000000', 16),
    6: int('-0x800000000000', 16),
    7: int('-0x80000000000000', 16),
    8: int('-0x8000000000000000', 16),
    9: int('-0x800000000000000000', 16),
    10: int('-0x80000000000000000000', 16),
    11: int('-0x8000000000000000000000', 16),
    12: int('-0x800000000000000000000000', 16),
    13: int('-0x80000000000000000000000000', 16),
    14: int('-0x8000000000000000000000000000', 16),
    15: int('-0x800000000000000000000000000000', 16),
    16: int('-0x80000000000000000000000000000000', 16),
    17: int('-0x8000000000000000000000000000000000', 16),
    18: int('-0x800000000000000000000000000000000000', 16),
    19: int('-0x80000000000000000000000000000000000000', 16),
    20: int('-0x8000000000000000000000000000000000000000', 16),
    21: int('-0x800000000000000000000000000000000000000000', 16),
    22: int('-0x80000000000000000000000000000000000000000000', 16),
    23: int('-0x8000000000000000000000000000000000000000000000', 16),
    24: int('-0x800000000000000000000000000000000000000000000000', 16),
    25: int('-0x80000000000000000000000000000000000000000000000000', 16),
    26: int('-0x8000000000000000000000000000000000000000000000000000', 16),
    27: int('-0x800000000000000000000000000000000000000000000000000000', 16),
    28: int('-0x80000000000000000000000000000000000000000000000000000000', 16),
    29: int('-0x8000000000000000000000000000000000000000000000000000000000', 16),
    30: int('-0x800000000000000000000000000000000000000000000000000000000000', 16),
    31: int('-0x80000000000000000000000000000000000000000000000000000000000000', 16),
    32: int('-0x8000000000000000000000000000000000000000000000000000000000000000', 16)
}

MAX_RING_BUFFER_LENGTH = 10
MAX_ARRAY_LENGTH = 2

class CircularSet[T]:
    def __init__(self, set_size: int = MAX_RING_BUFFER_LENGTH, initial_set: Iterable[T] | None = None) -> None:
        self._q = collections.deque[T](maxlen=set_size)
        if initial_set:
            self._q.extend(initial_set)

    @property
    def empty(self) -> bool:
        return len(self._q) == 0

    def add(self, value: T) -> None:
        if value not in self._q:
            self._q.append(value)
        else:
            self._q.remove(value)
            self._q.append(value)

    def head_and_rotate(self) -> T:
        value = self._q[-1]
        self._q.rotate(1)
        return value

    def discard(self, value: T) -> None:
        if value in self._q:
            self._q.remove(value)

    def __repr__(self) -> str:
        return repr(self._q)

FuzzTransactionInput = TypedDict('FuzzTransactionInput', {
    'account': 'HexAddress',
    'contract': 'HexAddress',
    'amount': int,
    'arguments': list[Any],
    'blocknumber': int | None,
    'timestamp': int | None,
    'gaslimit': int,
    'balance': NotRequired[int | None],
    'call_return': NotRequired[dict['HexAddress', Any]],
    'extcodesize': NotRequired[dict['HexAddress', int | None]],
    'returndatasize': NotRequired[dict['HexAddress', int | None]]
})

class Generator:
    def __init__(self, interface: dict[str, list[str]], bytecode: HexStr | None, accounts: list[HexAddress], contract: HexAddress) -> None:
        self.logger = initialize_logger('Generator')
        self.interface = interface
        self.bytecode = bytecode
        self.accounts = accounts
        self.contract = contract

        # Pools
        self.function_circular_buffer = CircularSet[str](set_size=len(self.interface), initial_set=set(self.interface))
        self.accounts_pool: dict[str, CircularSet[HexAddress]] = {}
        self.amounts_pool: dict[str, CircularSet[int]] = {}
        self.arguments_pool: dict[str, dict[int, CircularSet]] = {}
        self.timestamp_pool: dict[str, CircularSet[int]] = {}
        self.blocknumber_pool: dict[str, CircularSet[int]] = {}
        self.balance_pool: dict[str, CircularSet[int]] = {}
        self.callresult_pool: dict[str, dict[HexAddress, CircularSet]] = {}
        self.gaslimit_pool: dict[str, CircularSet[int]] = {}
        self.extcodesize_pool: dict[str, dict[HexAddress, CircularSet[int]]] = {}
        self.returndatasize_pool: dict[str, dict[HexAddress, CircularSet[int]]] = {}
        self.argument_array_sizes_pool: dict[str, dict[int, CircularSet[int]]] = {}
        self.strings_pool = CircularSet[str]()
        self.bytes_pool = CircularSet[bytes]()

    def init_pool_from_history(self, history_transactions: list[dict]) -> None:
        self.logger.info('Initializing pools from history')
        for transaction in history_transactions:
            if transaction['input'] != '':
                function_selector = transaction['input'][:10]
                data = bytes.fromhex(transaction['input'][10:])
                if function_selector in self.interface:
                    argument_types = self.interface[function_selector]
                    arguments = decode(argument_types, data)
                    for idx, arg in enumerate(arguments):
                        self.add_argument_to_pool(function_selector, idx, arg)
                        if argument_types[idx] == 'address':
                            self.add_account_to_pool(function_selector, arg)
                    self.add_account_to_pool(function_selector, transaction['from'])
                else:
                    self.logger.warning(f'Function selector {function_selector} not in abi interface')
            else:
                self.add_account_to_pool('fallback', transaction['from'])
        self.logger.info('Pools initialized')

    def generate_random_individual(self) -> list[FuzzTransactionInput]:
        individual: list[FuzzTransactionInput] = []

        function, argument_types = self.get_random_function_with_argument_types()
        arguments: list[Any] = [function]
        for index in range(len(argument_types)):
            arguments.append(self.get_random_argument(argument_types[index], function, index))
        individual.append({
            'account': self.get_random_account(function),
            'contract': self.contract,
            'amount': self.get_random_amount(function),
            'arguments': arguments,
            'blocknumber': self.get_random_blocknumber(function),
            'timestamp': self.get_random_timestamp(function),
            'gaslimit': self.get_random_gaslimit(function),
            'call_return': {},
            'extcodesize': {},
            'returndatasize': {}
        })

        address, call_return_value = self.get_random_callresult_and_address(function)
        if address is not None and call_return_value is not None:
            individual[-1]['call_return'] = {address: call_return_value}

        address, extcodesize_value = self.get_random_extcodesize_and_address(function)
        if address is not None and extcodesize_value is not None:
            individual[-1]['extcodesize'] = {address: extcodesize_value}

        address, value = self.get_random_returndatasize_and_address(function)
        if address is not None and value is not None:
            individual[-1]['returndatasize'] = {address: value}

        return individual

    def generate_random_input(self) -> FuzzTransactionInput:
        function, argument_types = self.get_random_function_with_argument_types()
        arguments = [function]
        for index in range(len(argument_types)):
            arguments.append(self.get_random_argument(argument_types[index], function, index))
        input: FuzzTransactionInput = {
            'account': self.get_random_account(function),
            'contract': self.contract,
            'amount': self.get_random_amount(function),
            'arguments': arguments,
            'blocknumber': self.get_random_blocknumber(function),
            'timestamp': self.get_random_timestamp(function),
            'gaslimit': self.get_random_gaslimit(function),
            'call_return': {},
            'extcodesize': {},
            'returndatasize': {}
        }

        address, value = self.get_random_returndatasize_and_address(function)
        if address is not None and value is not None:
            input['returndatasize'] = {address: value}

        return input

    def get_random_function_with_argument_types(self) -> tuple[str, list[str]]:
        function_hash = self.function_circular_buffer.head_and_rotate()
        if function_hash == 'constructor':
            function_hash = self.function_circular_buffer.head_and_rotate()
        return function_hash, self.interface[function_hash]

    #
    # TIMESTAMP
    #

    def add_timestamp_to_pool(self, function: str, timestamp: int) -> None:
        if not function in self.timestamp_pool:
            self.timestamp_pool[function] = CircularSet()
        self.timestamp_pool[function].add(timestamp)

    def get_random_timestamp(self, function: str) -> int | None:
        if function in self.timestamp_pool:
            return self.timestamp_pool[function].head_and_rotate()
        return None

    def remove_timestamp_from_pool(self, function: str, timestamp: int) -> None:
        if function in self.timestamp_pool:
            self.timestamp_pool[function].discard(timestamp)
            if self.timestamp_pool[function].empty:
                del self.timestamp_pool[function]

    #
    # BLOCKNUMBER
    #

    def add_blocknumber_to_pool(self, function: str, blocknumber: int) -> None:
        if not function in self.blocknumber_pool:
            self.blocknumber_pool[function] = CircularSet()
        self.blocknumber_pool[function].add(blocknumber)

    def get_random_blocknumber(self, function: str) -> int | None:
        if function in self.blocknumber_pool:
            return self.blocknumber_pool[function].head_and_rotate()
        return None

    def remove_blocknumber_from_pool(self, function: str, blocknumber: int) -> None:
        if function in self.blocknumber_pool:
            self.blocknumber_pool[function].discard(blocknumber)
            if self.blocknumber_pool[function].empty:
                del self.blocknumber_pool[function]

    #
    # BALANCE
    #

    def add_balance_to_pool(self, function: str, balance: int) -> None:
        if not function in self.balance_pool:
            self.balance_pool[function] = CircularSet()
        self.balance_pool[function].add(balance)

    def get_random_balance(self, function: str) -> int | None:
        if function in self.balance_pool:
            return self.balance_pool[function].head_and_rotate()
        return None

    #
    # CALL RESULT
    #

    def add_callresult_to_pool(self, function: str, address: HexAddress, result: Any) -> None:
        if not function in self.callresult_pool:
            self.callresult_pool[function] = {}
        if not address in self.callresult_pool[function]:
            self.callresult_pool[function][address] = CircularSet()
        self.callresult_pool[function][address].add(result)

    def get_random_callresult_and_address(self, function: str) -> tuple[HexAddress, Any] | tuple[None, None]:
        if function in self.callresult_pool:
            address = random.choice(list(self.callresult_pool[function].keys()))
            value = self.callresult_pool[function][address].head_and_rotate()
            return address, value
        return None, None

    def get_random_callresult(self, function: str, address: HexAddress) -> Any | None:
        if function in self.callresult_pool:
            if address in self.callresult_pool[function]:
                value = self.callresult_pool[function][address].head_and_rotate()
                return value
        return None

    def remove_callresult_from_pool(self, function: str, address: HexAddress, result: Any) -> None:
        if function in self.callresult_pool and address in self.callresult_pool[function]:
            self.callresult_pool[function][address].discard(result)
            if self.callresult_pool[function][address].empty:
                del self.callresult_pool[function][address]
                if len(self.callresult_pool[function]) == 0:
                    del self.callresult_pool[function]

    #
    # EXTCODESIZE
    #

    def add_extcodesize_to_pool(self, function: str, address: HexAddress, size: int) -> None:
        if not function in self.extcodesize_pool:
            self.extcodesize_pool[function] = {}
        if not address in self.extcodesize_pool[function]:
            self.extcodesize_pool[function][address] = CircularSet()
        self.extcodesize_pool[function][address].add(size)

    def get_random_extcodesize_and_address(self, function: str) -> tuple[HexAddress, int] | tuple[None, None]:
        if function in self.extcodesize_pool:
            address = random.choice(list(self.extcodesize_pool[function].keys()))
            return address, self.extcodesize_pool[function][address].head_and_rotate()
        return None, None

    def get_random_extcodesize(self, function: str, address: HexAddress) -> int | None:
        if function in self.extcodesize_pool:
            if address in self.extcodesize_pool[function]:
                return self.extcodesize_pool[function][address].head_and_rotate()
        return None

    def remove_extcodesize_from_pool(self, function: str, address: HexAddress, size: int) -> None:
        if function in self.extcodesize_pool and address in self.extcodesize_pool[function]:
            self.extcodesize_pool[function][address].discard(size)
            if self.extcodesize_pool[function][address].empty:
                del self.extcodesize_pool[function][address]
                if len(self.extcodesize_pool[function]) == 0:
                    del self.extcodesize_pool[function]

    #
    # RETURNDATASIZE
    #

    def add_returndatasize_to_pool(self, function: str, address: HexAddress, size: int) -> None:
        if not function in self.returndatasize_pool:
            self.returndatasize_pool[function] = {}
        if not address in self.returndatasize_pool[function]:
            self.returndatasize_pool[function][address] = CircularSet()
        self.returndatasize_pool[function][address].add(size)

    def get_random_returndatasize_and_address(self, function: str) -> tuple[HexAddress, int] | tuple[None, None]:
        if function in self.returndatasize_pool:
            address = random.choice(list(self.returndatasize_pool[function].keys()))
            return address, self.returndatasize_pool[function][address].head_and_rotate()
        return None, None

    def get_random_returndatasize(self, function: str, address: HexAddress) -> int | None:
        if function in self.returndatasize_pool:
            if address in self.returndatasize_pool[function]:
                return self.returndatasize_pool[function][address].head_and_rotate()
        return None

    def remove_returndatasize_from_pool(self, function: str, address: HexAddress, size: int) -> None:
        if function in self.returndatasize_pool and address in self.returndatasize_pool[function]:
            self.returndatasize_pool[function][address].discard(size)
            if self.returndatasize_pool[function][address].empty:
                del self.returndatasize_pool[function][address]
                if len(self.returndatasize_pool[function]) == 0:
                    del self.returndatasize_pool[function]

    #
    # GASLIMIT
    #

    def add_gaslimit_to_pool(self, function: str, gaslimit: int) -> None:
        if not function in self.gaslimit_pool:
            self.gaslimit_pool[function] = CircularSet()
        self.gaslimit_pool[function].add(gaslimit)

    def remove_gaslimit_from_pool(self, function: str, gaslimit: int) -> None:
        if function in self.gaslimit_pool:
            self.gaslimit_pool[function].discard(gaslimit)
            if self.gaslimit_pool[function].empty:
                del self.gaslimit_pool[function]

    def clear_gaslimits_in_pool(self, function: str) -> None:
        if function in self.gaslimit_pool:
            del self.gaslimit_pool[function]

    def get_random_gaslimit(self, function: str) -> int:
        if function in self.gaslimit_pool:
            return self.gaslimit_pool[function].head_and_rotate()
        return settings.GAS_LIMIT

    #
    # ACCOUNTS
    #

    def add_account_to_pool(self, function: str, account: HexAddress) -> None:
        if not function in self.accounts_pool:
            self.accounts_pool[function] = CircularSet()
        self.accounts_pool[function].add(account)

    def remove_account_from_pool(self, function: str, account: HexAddress) -> None:
        if function in self.accounts_pool:
            self.accounts_pool[function].discard(account)
            if self.accounts_pool[function].empty:
                del self.accounts_pool[function]

    def clear_accounts_in_pool(self, function: str) -> None:
        if function in self.accounts_pool:
            self.accounts_pool[function] = CircularSet()

    def get_random_account_from_pool(self, function: str) -> HexAddress:
        return self.accounts_pool[function].head_and_rotate()

    def get_random_account(self, function: str) -> HexAddress:
        if function in self.accounts_pool:
            return self.get_random_account_from_pool(function)
        else:
            return random.choice(self.accounts)

    #
    # AMOUNTS
    #

    def add_amount_to_pool(self, function: str, amount: int) -> None:
        if not function in self.amounts_pool:
            self.amounts_pool[function] = CircularSet()
        self.amounts_pool[function].add(amount)

    def remove_amount_from_pool(self, function: str, amount: int) -> None:
        if function in self.amounts_pool:
            self.amounts_pool[function].discard(amount)
            if self.amounts_pool[function].empty:
                del self.amounts_pool[function]

    def get_random_amount_from_pool(self, function: str) -> int:
        return self.amounts_pool[function].head_and_rotate()

    def get_random_amount(self, function: str) -> int:
        if function in self.amounts_pool:
            amount = self.get_random_amount_from_pool(function)
        else:
            amount = random.randint(0, 1)
            self.add_amount_to_pool(function, amount)
            self.add_amount_to_pool(function, 1 - amount)
        return amount

    #
    # STRINGS
    #

    def add_string_to_pool(self, string: str) -> None:
        self.strings_pool.add(string)


    def get_random_string_from_pool(self) -> str:
        return self.strings_pool.head_and_rotate()

    #
    # BYTES
    #

    def add_bytes_to_pool(self, string: bytes) -> None:
        self.bytes_pool.add(string)


    def get_random_bytes_from_pool(self) -> bytes:
        return self.bytes_pool.head_and_rotate()

    #
    # FUNCTION ARGUMENTS
    #

    def add_parameter_array_size(self, function: str, parameter_index: int, array_size: int) -> None:
        if function not in self.argument_array_sizes_pool:
            self.argument_array_sizes_pool[function] = {}
        if parameter_index not in self.argument_array_sizes_pool[function]:
            self.argument_array_sizes_pool[function][parameter_index] = CircularSet()
        self.argument_array_sizes_pool[function][parameter_index].add(min(array_size, MAX_ARRAY_LENGTH))

    def _get_parameter_array_size_from_pool(self, function: str, argument_index: int) -> int:
        return self.argument_array_sizes_pool[function][argument_index].head_and_rotate()

    def remove_parameter_array_size_from_pool(self, function: str, parameter_index: int, array_size: int) -> None:
        if function in self.argument_array_sizes_pool and parameter_index in self.argument_array_sizes_pool[function]:
            self.argument_array_sizes_pool[function][parameter_index].discard(array_size)
            if self.argument_array_sizes_pool[function][parameter_index].empty:
                del self.argument_array_sizes_pool[function][parameter_index]
                if len(self.argument_array_sizes_pool[function]) == 0:
                    del self.argument_array_sizes_pool[function]


    def add_argument_to_pool(self, function: str, argument_index: int, argument: Any) -> None:
        if isinstance(argument, list):
            for element in argument:
                self.add_argument_to_pool(function, argument_index, element)
            return
        if function not in self.arguments_pool:
            self.arguments_pool[function] = {}
        if argument_index not in self.arguments_pool[function]:
            self.arguments_pool[function][argument_index] = CircularSet()
        self.arguments_pool[function][argument_index].add(argument)

    def remove_argument_from_pool(self, function: str, argument_index: int, argument: Any) -> None:
        if isinstance(argument, list):
            for element in argument:
                self.remove_argument_from_pool(function, argument_index, element)
            return
        if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
            self.arguments_pool[function][argument_index].discard(argument)
            if self.arguments_pool[function][argument_index].empty:
                del self.arguments_pool[function][argument_index]
                if len(self.arguments_pool[function]) == 0:
                    del self.arguments_pool[function]

    def _get_random_argument_from_pool(self, function: str, argument_index: int) -> Any:
        return self.arguments_pool[function][argument_index].head_and_rotate()

    def get_random_argument(self, type: str, function: str, argument_index: int) -> Any:
        # Boolean
        if type.startswith('bool'):
            # Array
            if '[' in type and ']' in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        if self._get_random_argument_from_pool(function, argument_index) == 0:
                            array.append(False)
                        else:
                            array.append(True)
                    else:
                        if random.randint(0, 1) == 0:
                            array.append(False)
                        else:
                            array.append(True)
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    if self._get_random_argument_from_pool(function, argument_index) == 0:
                        return False
                    return True
                else:
                    if random.randint(0, 1) == 0:
                        return False
                    return True

        # Unsigned integer
        elif type.startswith('uint'):
            bytes = int(int(type.replace('uint', '').split('[')[0]) / 8)
            # Array
            if '[' in type and ']' in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(self.get_random_unsigned_integer(0, UINT_MAX[bytes]))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return self.get_random_unsigned_integer(0, UINT_MAX[bytes])

        # Signed integer
        elif type.startswith('int'):
            bytes = int(int(type.replace('int', '').split('[')[0]) / 8)
            # Array
            if '[' in type and ']' in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(self.get_random_signed_integer(INT_MIN[bytes], INT_MAX[bytes]))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return self.get_random_signed_integer(INT_MIN[bytes], INT_MAX[bytes])

        # Address
        elif type.startswith('address'):
            # Array
            if '[' in type and ']' in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(random.choice(self.accounts))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return random.choice(self.accounts)

        # String
        elif type.startswith('string'):
            # Array
            if '[' in type and ']' in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self.get_string(random.randint(0, MAX_ARRAY_LENGTH)))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                if self.strings_pool.empty:
                    self.add_string_to_pool(self.get_string(0))
                    self.add_string_to_pool(self.get_string(1))
                    self.add_string_to_pool(self.get_string(32))
                    self.add_string_to_pool(self.get_string(33))
                return self.get_random_string_from_pool()

        # Bytes1 ... Bytes32
        elif type.startswith('bytes1') or \
             type.startswith('bytes2') or \
             type.startswith('bytes3') or \
             type.startswith('bytes4') or \
             type.startswith('bytes5') or \
             type.startswith('bytes6') or \
             type.startswith('bytes7') or \
             type.startswith('bytes8') or \
             type.startswith('bytes9') or \
             type.startswith('bytes10') or \
             type.startswith('bytes11') or \
             type.startswith('bytes12') or \
             type.startswith('bytes13') or \
             type.startswith('bytes14') or \
             type.startswith('bytes15') or \
             type.startswith('bytes16') or \
             type.startswith('bytes17') or \
             type.startswith('bytes18') or \
             type.startswith('bytes19') or \
             type.startswith('bytes20') or \
             type.startswith('bytes21') or \
             type.startswith('bytes22') or \
             type.startswith('bytes23') or \
             type.startswith('bytes24') or \
             type.startswith('bytes25') or \
             type.startswith('bytes26') or \
             type.startswith('bytes27') or \
             type.startswith('bytes28') or \
             type.startswith('bytes29') or \
             type.startswith('bytes30') or \
             type.startswith('bytes31') or \
             type.startswith('bytes32'):
            length = int(type.replace('bytes', '').split('[')[0])
            # Array
            if '[' in type and ']' in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(self.get_random_bytes(length))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return self.get_random_bytes(random.randint(0, length))

        # Bytes
        elif type.startswith('bytes'):
            # Array
            if '[' in type and ']' in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self.get_random_bytes(random.randint(0, MAX_ARRAY_LENGTH)))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                if self.bytes_pool.empty:
                    self.add_bytes_to_pool(self.get_random_bytes(0))
                    self.add_bytes_to_pool(self.get_random_bytes(1))
                    self.add_bytes_to_pool(self.get_random_bytes(32))
                    self.add_bytes_to_pool(self.get_random_bytes(33))
                return self.get_random_bytes_from_pool()

        # Unknown type
        else:
            # self.logger.error('Unsupported type: '+str(type))
            raise ValueError('Unsupported type: '+str(type))

    def _get_array_sizes(self, argument_index: int, function: str, type: str) -> list[int]:
        sizes: list[int] = []
        for size in re.compile(r'\[(.*?)\]').findall(type):
            # Dynamic array
            if size == '':
                if function in self.argument_array_sizes_pool \
                        and argument_index in self.argument_array_sizes_pool[function]:
                    sizes.append(self._get_parameter_array_size_from_pool(function, argument_index))
                else:
                    sizes.append(random.randint(0, MAX_ARRAY_LENGTH))
            # Fixed size array
            else:
                sizes.append(int(size))
        return sizes

    @staticmethod
    def get_random_unsigned_integer(min: int, max: int) -> int:
        seed = int(random.uniform(-2, 2))
        if seed == -1:
            return random.choice([min, min + 1, min + 2])
        elif seed == 1:
            return random.choice([max, max - 1, max - 2])
        else:
            return random.randint(min, max)

    @staticmethod
    def get_random_signed_integer(min: int, max: int) -> int:
        seed = int(random.uniform(-2, 2))
        if seed == -1:
            return random.choice([0, -1, min, min + 1])
        elif seed == 1:
            return random.choice([0, 1, max, max - 1])
        else:
            return random.randint(min, max)

    @staticmethod
    def get_string(length: int) -> str:
        return ''.join('A' for _ in range(length))

    @staticmethod
    def get_random_bytes(length: int) -> bytes:
        return bytearray(random.getrandbits(8) for _ in range(length))
