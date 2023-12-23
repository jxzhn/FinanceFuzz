#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import TypedDict, Any, cast

from utils.utils import get_pcs_and_jumpis

class Source:
    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.content = self._load_content()
        self.line_break_positions = self._load_line_break_positions()

    def _load_content(self) -> str:
        with open(self.filename, 'r') as f:
            content = f.read()
        return content

    def _load_line_break_positions(self) -> list[int]:
        return [i for i, letter in enumerate(self.content) if letter == '\n']

CodeDict = TypedDict('CodeDict', {
    '.auxdata': Any,
    '.code': list['PositionDict'],
    '.data': dict[str, 'CodeDict'],
})

PositionDict = TypedDict('AsmDict', {
    'begin': int,
    'end': int,
    'name': str,
})

LineColumnDict = TypedDict('LineColumnDict', {
    'line': int,
    'column': int,
})

LCPositionDict = TypedDict('LCPositionDict', {
    'begin': LineColumnDict | None,
    'end': LineColumnDict | None,
})

class SourceMap:
    sources = {}

    def __init__(self, cname: str, compiler_output: dict) -> None:
        self.cname = cname
        self.compiler_output = compiler_output
        self.position_groups = self._load_position_groups_standard_json()
        self.source = self._get_source()
        self.positions = self._get_positions()
        self.instr_positions = self._get_instr_positions()

    def get_source_code(self, pc: int) -> str:
        try:
            pos = self.instr_positions[pc]
        except:
            return ''
        begin = pos['begin']
        end = pos['end']
        return self.source.content[begin:end]

    def get_buggy_line(self, pc: int) -> str:
        #print(self.instr_positions)
        try:
            pos = self.instr_positions[pc]
        except:
            return ''
        #location = self.get_location(pc)
        #print(location)
        try:
            #begin = self.source.line_break_positions[location['begin']['line'] - 1] + 1
            begin = pos['begin']
            end = pos['end']
            #print(begin)
            #print(end)
            #print(self.source.content[begin:end])
            return self.source.content[begin:end]
        except:
            return ''

    def get_location(self, pc: int) -> LCPositionDict:
        pos = self.instr_positions[pc]
        return self._convert_offset_to_line_column(pos)

    def _get_source(self) -> Source:
        fname = self.get_filename()
        if fname not in SourceMap.sources:
            SourceMap.sources[fname] = Source(fname)
        return SourceMap.sources[fname]

    def _load_position_groups_standard_json(self) -> dict:
        return self.compiler_output['contracts']

    def _get_positions(self) -> list[PositionDict | None]:
        filename, contract_name = self.cname.split(':')
        asm = cast(CodeDict, self.position_groups[filename][contract_name]['evm']['legacyAssembly']['.data']['0'])
        positions = cast(list[PositionDict | None], asm['.code'])
        while(True):
            try:
                positions.append(None)
                positions += asm['.data']['0']['.code']
                asm = asm['.data']['0']
            except:
                break
        return positions

    def _get_instr_positions(self) -> dict[int, PositionDict]:
        j = 0
        instr_positions: dict[int, PositionDict] = {}
        try:
            filename, contract_name = self.cname.split(':')
            bytecode: str = self.compiler_output['contracts'][filename][contract_name]['evm']['deployedBytecode']['object']
            pcs = get_pcs_and_jumpis(bytecode)[0]
            for i in range(len(self.positions)):
                pos = self.positions[i]
                if pos and pos['name'] != 'tag':
                    instr_positions[pcs[j]] = pos
                    j += 1
            return instr_positions
        except:
            return instr_positions

    def _convert_offset_to_line_column(self, pos: PositionDict) -> LCPositionDict:
        ret: LCPositionDict = {
            'begin': None,
            'end': None
        }
        if pos['begin'] >= 0 and (pos['end'] - pos['begin'] + 1) >= 0:
            ret['begin'] = self._convert_from_char_pos(pos['begin'])
            ret['end'] = self._convert_from_char_pos(pos['end'])
        return ret

    def _convert_from_char_pos(self, pos: int) -> LineColumnDict:
        line = self._find_lower_bound(pos, self.source.line_break_positions)
        col = 0
        if line in self.source.line_break_positions:
            if self.source.line_break_positions[line] != pos:
                line += 1
            begin_col = 0 if line == 0 else self.source.line_break_positions[line - 1] + 1
            col = pos - begin_col
        else:
            line += 1
        return {'line': line, 'column': col}

    def _find_lower_bound(self, target: int, array: list[int]) -> int:
        start = 0
        length = len(array)
        while length > 0:
            half = length >> 1
            middle = start + half
            if array[middle] <= target:
                length = length - 1 - half
                start = middle + 1
            else:
                length = half
        return start - 1

    def get_filename(self) -> str:
        return self.cname.split(':')[0]
