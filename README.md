# PE Backdooring Tool

A Python-based tool for analyzing and backdooring Portable Executable (PE) files via reverse shell TCP, with a focus on code cave discovery and shellcode injection.

## Features

- **PE File Analysis**
  - Architecture detection (32/64-bit)
  - Security features analysis (ASLR, DEP, SEH, etc.)
  - File headers inspection
  - Section information extraction

- **Code Cave Detection**
  - Automated discovery of code caves in executable sections
  - Configurable minimum size requirements
  - Smart selection of optimal injection locations

- **Shellcode Injection**
  - State-preserving injection with proper stack alignment for 64-bit
  - Automatic prologue and epilogue generation
  - Support for position-independent shellcode
  - Maintains original program flow

## Technical Flow

### Injection Process

1. **Initial PE Analysis**
   - Load and parse the PE file
   - Verify architecture (64-bit support)
   - Check security features
   - Analyze sections and headers

2. **Code Cave Discovery**
   - Scan executable sections for code caves
   - Filter caves based on minimum size requirements
   - Size calculation includes:
     - Shellcode size
     - Prologue/epilogue code
     - Jump instructions
     - Additional padding

3. **Entry Point Analysis**
   - Locate the entry point section
   - Find first CALL instruction after entry point
   - Find first JMP instruction after entry point
   - These instructions will be modified to redirect flow

4. **Shellcode Preparation**
   - Generate stack-aligned prologue
     - Save all registers (RCX, RDX, RBX, RBP, RSI, RDI, R8-R15)
     - Save RFLAGS
     - Align stack to 16 bytes
   - Append actual shellcode
   - Generate epilogue
     - Restore all registers
     - Restore RFLAGS
     - Restore stack alignment

5. **Injection Process**
   ```
   Original Flow:
   Entry Point -> CALL original_function -> JMP next_instruction

   Modified Flow:
   Entry Point -> JMP code_cave -> 
                    [Execute Shellcode] -> 
                    CALL original_function ->
                    JMP next_instruction
   ```

6. **Control Flow Modification**
   - Calculate relative offsets for:
     - Entry point to code cave jump
     - Code cave to original CALL target
     - Return jump to original flow
   - Modify original CALL instruction to JMP to code cave
   - Write shellcode to code cave
   - Add final jump back to original flow

7. **Verification**
   - Verify all offsets are correct
   - Ensure stack alignment is maintained
   - Confirm all register states are preserved

## Components

### 1. PE Parser (`utils/parser.py`)
- Handles PE file parsing and analysis
- Provides utilities for:
  - RVA to raw offset conversion
  - Instruction disassembly
  - Memory reading/writing operations
  - Section analysis

### 2. Code Cave Finder (`utils/codecaver.py`)
- Identifies suitable code caves in PE sections
- Implements algorithms for finding optimal injection points
- Validates cave sizes and section permissions

### 3. Shellcode Injector (`utils/injector.py`)
- Manages the shellcode injection process
- Handles:
  - Stack alignment
  - Register state preservation
  - Control flow modification
  - Return flow preservation

### 4. Logger (`utils/logger.py`)
- Provides formatted output for different message types
- Supports debug, error, and success messages
- Implements section-based output formatting

## Requirements

- Python 3.x
- pefile
- capstone

## Usage

```bash
python main.py <path_to_pe_file>