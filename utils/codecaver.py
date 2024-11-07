from typing import Dict, List, Tuple, Any
from utils.logger import print_debug, print_success


class CodeCaver:
    def __init__(self, pe_parser):
        self.pe_parser = pe_parser
        self.pe = pe_parser.pe

    def find_code_caves(self, min_size: int = 100, byte_pattern: bytes = b'\x00') -> Dict[str, List[Tuple[int, int]]]:
        caves = {}

        for section in self.pe.sections:
            section_name = section.Name.decode().rstrip('\x00')
            caves[section_name] = []

            data = section.get_data()
            cave_start = 0
            pattern_count = 0

            for i in range(len(data)):
                if data[i:i + len(byte_pattern)] == byte_pattern:
                    if pattern_count == 0:
                        cave_start = i
                    pattern_count += 1
                else:
                    if pattern_count >= min_size:
                        caves[section_name].append((
                            section.PointerToRawData + cave_start,
                            pattern_count
                        ))
                    pattern_count = 0

            if pattern_count >= min_size:
                caves[section_name].append((
                    section.PointerToRawData + cave_start,
                    pattern_count
                ))

        return caves

    def find_best_cave(self, caves: Dict[str, List[Tuple[int, int]]], required_size: int) -> tuple[tuple[
        int, int], Any, Any] | tuple[None, None, None]:
        best_cave = None
        best_section = None

        for section in self.pe.sections:
            section_name = section.Name.decode().rstrip('\x00')
            if section.Characteristics & 0x20000000:  # Check if section is executable
                if section_name in caves and caves[section_name]:
                    for cave_addr, cave_size in caves[section_name]:
                        if cave_size >= required_size:
                            return (cave_addr, cave_size), section, section_name

        return None, None, None
