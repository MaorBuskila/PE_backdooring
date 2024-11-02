import pefile
import struct
from typing import Dict, List, Tuple, Optional, Union
import binascii

class PEAnalyzer:
    def __init__(self, pe_path: str):
        """Initialize PE analyzer with file path"""
        self.pe_path = pe_path
        self.pe = pefile.PE(pe_path)

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
                'Entropy': section.get_entropy()
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
                            section.VirtualAddress + cave_start,
                            pattern_count
                        ))
                    pattern_count = 0
                    
            # Check for cave at end of section
            if pattern_count >= min_size:
                caves[section_name].append((
                    section.VirtualAddress + cave_start,
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