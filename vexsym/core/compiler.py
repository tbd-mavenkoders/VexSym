"""
Compiler Harness Module

Compiles decompiled C/C++ source code into a binary format
that angr can analyze alongside the original binary.

Key Features:
- Handles both C and C++ compilation
- Uses -O0 to preserve code structure
- Disables stack protector to avoid false positives
- Provides detailed compilation error reporting
"""

import subprocess
import tempfile
import os
import logging
from pathlib import Path
from typing import Optional, List

logger = logging.getLogger(__name__)


# =============================================================================
# GHIDRA TYPE DEFINITIONS HEADER
# =============================================================================
GHIDRA_TYPES_HEADER = """// Standard headers
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>

// Ghidra type aliases
typedef unsigned int    uint;
typedef unsigned long   ulong;
typedef unsigned char   uchar;
typedef unsigned short  ushort;
typedef int8_t          int8;
typedef int16_t         int16;
typedef int32_t         int32;
typedef int64_t         int64;
typedef uint8_t         uint8;
typedef uint16_t        uint16;
typedef uint32_t        uint32;
typedef uint64_t        uint64;
typedef uint8_t         byte;
typedef uint8_t         undefined;
typedef uint16_t        undefined2;
typedef uint32_t        undefined4;
typedef uint64_t        undefined8;
typedef unsigned int    BOT;

"""

# C++ specific header with extern "C" wrapper
CPP_HEADER_WITH_EXTERN_C = """// Standard headers
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>

// Ghidra type aliases
typedef unsigned int    uint;
typedef unsigned long   ulong;
typedef unsigned char   uchar;
typedef unsigned short  ushort;
typedef int8_t          int8;
typedef int16_t         int16;
typedef int32_t         int32;
typedef int64_t         int64;
typedef uint8_t         uint8;
typedef uint16_t        uint16;
typedef uint32_t        uint32;
typedef uint64_t        uint64;
typedef uint8_t         byte;
typedef uint8_t         undefined;
typedef uint16_t        undefined2;
typedef uint32_t        undefined4;
typedef uint64_t        undefined8;
typedef unsigned int    BOT;

#ifdef __cplusplus
extern "C" {
#endif

"""

CPP_FOOTER = """
#ifdef __cplusplus
}
#endif
"""


def preprocess_c_code(source_code: str) -> str:
    """
    Preprocess C code by adding Ghidra type definitions.
    """
    # Check if types already defined
    if 'typedef unsigned int' in source_code and 'uint' in source_code:
        return source_code
    return GHIDRA_TYPES_HEADER + source_code


def preprocess_cpp_code(source_code: str) -> str:
    """
    Preprocess C++ code for angr analysis.
    
    KEY INSIGHT: We MUST use extern "C" to prevent name mangling in the
    decompiled binary. This ensures angr can find 'func0' instead of '_Z5func0f'.
    
    For STL-heavy code, we compile with -fno-exceptions -fno-rtti to simplify.
    The extern "C" block wraps the code AFTER standard headers.
    """
    # Check if code uses C++ STL (vector, string, etc.)
    uses_stl = any(h in source_code for h in [
        '#include <vector>', '#include <string>', '#include <map>',
        '#include <set>', '#include <list>', '#include <algorithm>',
        '#include <iostream>', '#include <fstream>', '#include <sstream>',
        'std::', 'using namespace std'
    ])
    
    if uses_stl:
        # STL code: We still need extern "C" around the TARGET FUNCTION only
        # Extract and wrap just the function definitions
        # For now, add headers before and wrap everything after in extern "C"
        stl_header = """// STL includes must be OUTSIDE extern "C"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

// Extract STL includes from source
"""
        # Move STL includes to header
        lines = source_code.split('\n')
        stl_includes = []
        code_lines = []
        for line in lines:
            if line.strip().startswith('#include <') and any(s in line for s in ['vector', 'string', 'map', 'set', 'list', 'algorithm', 'iostream']):
                stl_includes.append(line)
            else:
                code_lines.append(line)
        
        result = stl_header
        for inc in stl_includes:
            result += inc + '\n'
        
        # Add type definitions
        result += """
// Ghidra type aliases
typedef unsigned int    uint;
typedef unsigned long   ulong;

// extern "C" for function to prevent mangling
#ifdef __cplusplus
extern "C" {
#endif

"""
        result += '\n'.join(code_lines)
        result += CPP_FOOTER
        return result
    else:
        # Non-STL C++ code: Wrap everything in extern "C"
        if 'extern "C"' in source_code:
            # Already has extern "C"
            if 'typedef unsigned int' not in source_code:
                return GHIDRA_TYPES_HEADER + source_code
            return source_code
        
        # Use full header with extern "C"
        return CPP_HEADER_WITH_EXTERN_C + source_code + CPP_FOOTER


class CompilationError(Exception):
    """Raised when source code compilation fails."""
    pass


def compile_source(
    source_code: str,
    is_cpp: bool = False,
    output_path: Optional[str] = None,
    extra_flags: Optional[List[str]] = None,
    include_dirs: Optional[List[str]] = None,
) -> str:
    """
    Compile decompiled source code into a binary executable.
    
    Args:
        source_code: The C/C++ source code to compile
        is_cpp: Whether the code is C++ (True) or C (False)
        output_path: Optional path for the output binary. If None, uses temp file.
        extra_flags: Additional compiler flags to pass
        include_dirs: Additional include directories
        
    Returns:
        Path to the compiled binary
        
    Raises:
        CompilationError: If compilation fails
        
    Example:
        >>> code = 'int main() { return 42; }'
        >>> binary_path = compile_source(code, is_cpp=False)
        >>> # binary_path can now be analyzed with angr
    """
    compiler = "g++" if is_cpp else "gcc"
    extension = ".cpp" if is_cpp else ".c"
    
    # For C++, we need special handling - extern "C" must wrap ONLY the function
    # definitions, not the headers or STL includes
    if is_cpp:
        source_code = preprocess_cpp_code(source_code)
    else:
        source_code = preprocess_c_code(source_code)
    
    # Add dummy main if not present (for standalone function compilation)
    if "int main(" not in source_code and "int main (" not in source_code:
        source_code = source_code + "\nint main() { return 0; }\n"
    
    # Create source file
    with tempfile.NamedTemporaryFile(
        suffix=extension, 
        delete=False, 
        mode='w',
        encoding='utf-8'
    ) as src_file:
        src_file.write(source_code)
        src_path = src_file.name
    
    logger.info(f"Created source file: {src_path}")
    
    # Determine output path
    if output_path is None:
        bin_path = src_path + ".bin"
    else:
        bin_path = output_path
    
    # Build compiler command
    # Critical flags:
    # -O0: No optimization, preserves structure for debugging
    # -fno-stack-protector: Prevents canary checks that clutter VEX IR
    # -w: Suppress warnings (we only care if it links)
    # -no-pie: Helps with address alignment (though CLE handles PIE well)
    # -lm: Link math library for fabs, sqrt, etc.
    cmd = [
        compiler,
        "-O0",                    # No optimization
        "-fno-stack-protector",   # No stack canaries
        "-w",                     # Suppress warnings
        "-no-pie",                # Disable position-independent executable
        "-o", bin_path,
        src_path,
        "-lm"                     # Link math library
    ]
    
    # Add extra flags if provided
    if extra_flags:
        cmd.extend(extra_flags)
    
    # Add include directories
    if include_dirs:
        for inc_dir in include_dirs:
            cmd.extend(["-I", inc_dir])
    
    logger.info(f"Compiling with command: {' '.join(cmd)}")
    
    try:
        # Run compilation
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30  # 30 second timeout for compilation
        )
        
        if result.returncode != 0:
            error_msg = f"Compilation failed with return code {result.returncode}\n"
            error_msg += f"STDOUT:\n{result.stdout}\n"
            error_msg += f"STDERR:\n{result.stderr}"
            logger.error(error_msg)
            raise CompilationError(error_msg)
        
        logger.info(f"Successfully compiled to: {bin_path}")
        
        # Verify the binary was created
        if not os.path.exists(bin_path):
            raise CompilationError(f"Binary not created at expected path: {bin_path}")
        
        return bin_path
        
    except subprocess.TimeoutExpired:
        error_msg = "Compilation timed out after 30 seconds"
        logger.error(error_msg)
        raise CompilationError(error_msg)
    
    except Exception as e:
        error_msg = f"Unexpected compilation error: {str(e)}"
        logger.error(error_msg)
        raise CompilationError(error_msg)
    
    finally:
        # Clean up source file
        try:
            if os.path.exists(src_path):
                os.remove(src_path)
                logger.debug(f"Cleaned up source file: {src_path}")
        except Exception as e:
            logger.warning(f"Failed to clean up source file {src_path}: {e}")


def compile_with_debugging_symbols(
    source_code: str,
    is_cpp: bool = False,
    output_path: Optional[str] = None,
) -> str:
    """
    Compile source with debugging symbols enabled.
    
    Useful for detailed analysis and debugging, but may affect
    the exact binary structure.
    
    Args:
        source_code: The C/C++ source code to compile
        is_cpp: Whether the code is C++ (True) or C (False)
        output_path: Optional path for the output binary
        
    Returns:
        Path to the compiled binary with debug symbols
    """
    extra_flags = ["-g", "-ggdb"]  # Include debug symbols
    return compile_source(source_code, is_cpp, output_path, extra_flags)


def verify_compiler_availability() -> dict:
    """
    Check if required compilers are available.
    
    Returns:
        Dictionary with compiler availability and versions
    """
    result = {
        "gcc_available": False,
        "gcc_version": None,
        "gpp_available": False,
        "gpp_version": None,
    }
    
    # Check GCC
    try:
        gcc_output = subprocess.check_output(
            ["gcc", "--version"],
            stderr=subprocess.STDOUT,
            text=True
        )
        result["gcc_available"] = True
        result["gcc_version"] = gcc_output.split('\n')[0]
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.warning("GCC not found")
    
    # Check G++
    try:
        gpp_output = subprocess.check_output(
            ["g++", "--version"],
            stderr=subprocess.STDOUT,
            text=True
        )
        result["gpp_available"] = True
        result["gpp_version"] = gpp_output.split('\n')[0]
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.warning("G++ not found")
    
    return result
