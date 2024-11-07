import pefile
from typing import Dict, List, Tuple, Optional, Union
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from utils.logger import *


class PEParser:
    def __init__(self, pe_path: str):
        self.pe_path = pe_path
        self.pe = pefile.PE(pe_path)
        self.disassembler = self._init_disassembler()

    def _init_disassembler(self):
        mode = CS_MODE_64 if self.pe.FILE_HEADER.Machine == 0x8664 else CS_MODE_32
        return Cs(CS_ARCH_X86, mode)

    def get_file_headers(self) -> Dict:
        return {
            'Machine': hex(self.pe.FILE_HEADER.Machine),
            'TimeDateStamp': self.pe.FILE_HEADER.TimeDateStamp,
            'NumberOfSections': self.pe.FILE_HEADER.NumberOfSections,
            'Characteristics': hex(self.pe.FILE_HEADER.Characteristics),
            'EntryPoint': hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'ImageBase': hex(self.pe.OPTIONAL_HEADER.ImageBase),
            'Subsystem': hex(self.pe.OPTIONAL_HEADER.Subsystem)
        }

    def check_pe_architecture(self) -> str:
        if self.pe.FILE_HEADER.Machine == 0x8664:
            return "64-bit"
        elif self.pe.FILE_HEADER.Machine == 0x014c:
            return "32-bit"
        return "Unknown architecture"

    def get_sections_info(self) -> List[Dict]:
        return [{
            'Name': section.Name.decode().rstrip('\x00'),
            'VirtualAddress': hex(section.VirtualAddress),
            'VirtualSize': hex(section.Misc_VirtualSize),
            'RawSize': hex(section.SizeOfRawData),
            'Characteristics': hex(section.Characteristics),
        } for section in self.pe.sections]

    def check_security_features(self) -> Dict[str, bool]:
        characteristics = self.pe.OPTIONAL_HEADER.DllCharacteristics
        return {
            'ASLR': bool(characteristics & 0x0040),
            'DEP': bool(characteristics & 0x0100),
            'SEH': bool(characteristics & 0x0400),
            'SafeSEH': bool(characteristics & 0x0400),
            'CFG': bool(characteristics & 0x4000),
            'Integrity': bool(characteristics & 0x8000)
        }
    def rva_to_raw(self, rva: int, section_name: str = None) -> int:
        """Convert RVA to raw file offset"""
        if section_name:
            for section in self.pe.sections:
                curr_name = section.Name.decode().rstrip('\x00')
                if curr_name == section_name:
                    # Check boundaries based on SizeOfRawData to avoid misalignment issues
                    if section.VirtualAddress <= rva < section.VirtualAddress + section.SizeOfRawData:
                        raw_offset = section.PointerToRawData + (rva - section.VirtualAddress)
                        print(f"[DEBUG] Raw Offset: 0x{raw_offset:08x}")
                        return raw_offset
                else:
                    print(f"[ERROR] RVA 0x{rva:08x} out of bounds for section {section_name}")
        raise ValueError(f"Could not convert RVA 0x{rva:08x} to raw offset in section {section_name}")

    def read_bytes(self, rva: int, size: int, section_name) -> bytes:
        """Read bytes from the PE file at specified RVA"""
        raw_offset = self.rva_to_raw(rva, section_name)
        with open(self.pe_path, 'rb') as f:
            f.seek(raw_offset)
            return f.read(size)

    def write_bytes(self, offset: int, data: bytes) -> None:
        """Write bytes to the PE file at specified offset"""
        with open(self.pe_path, 'r+b') as f:
            f.seek(offset)
            f.write(data)

    def find_first_instruction(self, instruction: str, section_name: str, start_rva: int = None) -> Optional[Dict]:
        """Find the first occurrence of a specific instruction"""
        print_subheader(f"Searching for First '{instruction.upper()}' Instruction")
        try:
            target_section = None
            for section in self.pe.sections:
                if section.Name.decode().rstrip('\x00') == section_name:
                    target_section = section
                    break

            if not target_section:
                print_error(f"Section {section_name} not found")
                return None

            search_start = start_rva if start_rva else target_section.VirtualAddress
            search_size = target_section.SizeOfRawData

            print_debug(f"Search start: 0x{search_start:08x}")
            print_debug(f"Search size: {search_size} bytes")

            section_data = self.read_bytes(search_start, search_size, section_name)

            for insn in self.disassembler.disasm(section_data, search_start):
                if insn.mnemonic.lower() == instruction.lower():
                    result = {
                        'address': insn.address,
                        'bytes': bytes(insn.bytes),
                        'size': len(insn.bytes),
                        'mnemonic': insn.mnemonic,
                        'op_str': insn.op_str
                    }
                    print_success(f"Found {instruction} at 0x{insn.address:08x}")
                    print_debug(f"Instruction: {insn.mnemonic} {insn.op_str}")
                    print_debug(f"Size: {len(insn.bytes)} bytes")
                    return result

            print_error(f"No {instruction} instruction found")
            return None

        except Exception as e:
            print_error(f"Error finding instruction: {str(e)}")
            return None

    def print_instructions(self, address: int, size: int = 32, section_name: str = None) -> List[Dict]:
        """
        Disassemble and print instructions at specified address

        Args:
            address: RVA of the code to disassemble
            size: Number of bytes to disassemble (default: 32)
            section_name: Name of the section containing the code

        Returns:
            List of dictionaries containing instruction details
            :param self:
        """
        try:
            # Read the bytes at the specified address
            code_bytes = self.read_bytes(address, size, section_name)

            instructions = []
            print(f"\nDisassembly at address 0x{address:08x}:")
            print("-" * 50)

            # Disassemble the code
            for insn in self.disassembler.disasm(code_bytes, address):
                instruction = {
                    'address': f"0x{insn.address:08x}",
                    'bytes': ' '.join([f"{b:02x}" for b in insn.bytes]),
                    'mnemonic': insn.mnemonic,
                    'op_str': insn.op_str
                }
                instructions.append(instruction)

                # Print formatted instruction
                print(f"0x{insn.address:08x}: {instruction['bytes']:24} {insn.mnemonic:8} {insn.op_str}")

            return instructions
        except Exception as e:
            print(f"[-] Failed to disassemble at address 0x{address:08x}: {str(e)}")
            return []
