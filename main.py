from utils.parser import PEAnalyzer
import sys
import json

def print_section(title: str, content: any, indent: int = 0):
    """Helper function to print formatted sections"""
    print("\n" + "=" * 50)
    print(f"{title}:")
    print("-" * 50)
    if isinstance(content, dict):
        for key, value in content.items():
            print(" " * indent + f"{key}: {value}")
    elif isinstance(content, list):
        for item in content:
            if isinstance(item, dict):
                for k, v in item.items():
                    print(" " * indent + f"{k}: {v}")
                print("-" * 30)
            else:
                print(" " * indent + str(item))
    else:
        print(" " * indent + str(content))

def main():
    # if len(sys.argv) != 2:
    #     print("Usage: python main.py <path_to_pe_file>")
    #     sys.exit(1)

    # pe_path = sys.argv[1]
    pe_path = "C:\\Users\\MaorBuskila\\Documents\\calc.exe"
    try:
        analyzer = PEAnalyzer(pe_path)
        
        # Security features check
        print_section("Security Features", analyzer.check_aslr())
        
        # # Basic headers
        # print_section("File Headers", analyzer.get_file_headers())
        
        # # Sections
        # print_section("Sections", analyzer.get_sections_info())
        
        # # Imports
        # imports = analyzer.get_imports()
        # print_section("Imports", {
        #     dll: f"{len(funcs)} functions" 
        #     for dll, funcs in imports.items()
        # })
        
        # # Exports
        # exports = analyzer.get_exports()
        # print_section("Exports", exports)
        
        # Code caves
        caves = analyzer.find_code_caves(min_size=100)
        print_section("Code Caves", {
            section: [f"Offset: {hex(offset)}, Size: {size}" 
                     for offset, size in caves_list]
            for section, caves_list in caves.items()
            if caves_list
        })
        
        # # Obfuscation detection
        # print_section("Section Entropy (Possible Obfuscation)", 
        #              analyzer.detect_obfuscation())
        
        # # Data directories
        # print_section("Data Directories", analyzer.get_data_directories())
        
        # # Optional: Extract strings
        # strings = analyzer.extract_strings(min_length=8)
        # print_section("Interesting Strings (First 10)", strings[:10])

    except Exception as e:
        print(f"Error analyzing PE file: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 