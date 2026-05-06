"""
Angr Project Loader Module

Loads both the original binary and the recompiled decompiled binary
into angr projects for symbolic execution analysis.

Key Features:
- Uses CLE for binary loading
- Disables auto_load_libs for performance
- Handles various binary formats (ELF, PE, etc.)
- Provides detailed error reporting
"""

import angr
import logging
from typing import Tuple, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class ProjectLoadError(Exception):
    """Raised when binary loading fails."""
    pass


def load_projects(
    original_bin_path: str,
    decompiled_bin_path: str,
    auto_load_libs: bool = False,
    main_opts: Optional[dict] = None,
) -> Tuple[angr.Project, angr.Project]:
    """
    Load both binaries into angr projects.
    
    Args:
        original_bin_path: Path to the original binary
        decompiled_bin_path: Path to the recompiled decompiled binary
        auto_load_libs: Whether to load shared libraries (default: False for speed)
        main_opts: Additional options for the main binary loader
        
    Returns:
        Tuple of (original_project, decompiled_project)
        
    Raises:
        ProjectLoadError: If loading fails
        
    Example:
        >>> proj_orig, proj_dec = load_projects("original.bin", "decompiled.bin")
        >>> print(f"Original arch: {proj_orig.arch}")
        >>> print(f"Decompiled arch: {proj_dec.arch}")
    
    Notes:
        - auto_load_libs=False is crucial for performance
        - It prevents angr from lifting libc.so, ld.so, etc.
        - We only verify logic within the binary, not libc behavior
    """
    # Validate paths
    if not Path(original_bin_path).exists():
        raise ProjectLoadError(f"Original binary not found: {original_bin_path}")
    
    if not Path(decompiled_bin_path).exists():
        raise ProjectLoadError(f"Decompiled binary not found: {decompiled_bin_path}")
    
    logger.info(f"Loading original binary: {original_bin_path}")
    logger.info(f"Loading decompiled binary: {decompiled_bin_path}")
    
    # Default loader options
    default_opts = {
        'auto_load_libs': auto_load_libs,
        'load_debug_info': False,  # Skip debug info for speed
    }
    
    if main_opts:
        default_opts.update(main_opts)
    
    try:
        # Load original binary
        proj_orig = angr.Project(
            original_bin_path,
            **default_opts
        )
        logger.info(f"Original binary loaded: {proj_orig.arch} architecture")
        logger.info(f"Original entry point: {hex(proj_orig.entry)}")
        
    except Exception as e:
        error_msg = f"Failed to load original binary: {str(e)}"
        logger.error(error_msg)
        raise ProjectLoadError(error_msg)
    
    try:
        # Load decompiled binary
        proj_dec = angr.Project(
            decompiled_bin_path,
            **default_opts
        )
        logger.info(f"Decompiled binary loaded: {proj_dec.arch} architecture")
        logger.info(f"Decompiled entry point: {hex(proj_dec.entry)}")
        
    except Exception as e:
        error_msg = f"Failed to load decompiled binary: {str(e)}"
        logger.error(error_msg)
        raise ProjectLoadError(error_msg)
    
    # Verify architecture compatibility
    if proj_orig.arch.name != proj_dec.arch.name:
        warning_msg = (
            f"Architecture mismatch: "
            f"original={proj_orig.arch.name}, "
            f"decompiled={proj_dec.arch.name}"
        )
        logger.warning(warning_msg)
        # Not fatal, but may cause issues
    
    return proj_orig, proj_dec


def get_project_info(project: angr.Project) -> dict:
    """
    Extract detailed information from an angr project.
    
    Args:
        project: The angr project to inspect
        
    Returns:
        Dictionary containing project metadata
    """
    info = {
        "filename": project.filename,
        "architecture": project.arch.name,
        "bits": project.arch.bits,
        "entry_point": hex(project.entry),
        "endness": str(project.arch.memory_endness),
        "base_address": hex(project.loader.main_object.mapped_base),
        "min_addr": hex(project.loader.min_addr),
        "max_addr": hex(project.loader.max_addr),
        "has_plt": hasattr(project.loader.main_object, 'plt'),
    }
    
    # Get loaded objects
    info["loaded_objects"] = []
    for obj in project.loader.all_objects:
        info["loaded_objects"].append({
            "name": obj.binary,
            "base": hex(obj.mapped_base) if obj.mapped_base else "unmapped",
        })
    
    return info


def find_function_in_project(
    project: angr.Project,
    func_name: str,
) -> Optional[int]:
    """
    Find a function by name in the project.
    
    Args:
        project: The angr project
        func_name: Name of the function to find
        
    Returns:
        Function address if found, None otherwise
    """
    # Try to find the symbol
    sym = project.loader.find_symbol(func_name)
    if sym:
        logger.info(f"Found function '{func_name}' at {hex(sym.rebased_addr)}")
        return sym.rebased_addr
    
    # Try with name mangling for C++
    # Common C++ name mangling patterns
    mangled_variants = [
        f"_Z{len(func_name)}{func_name}",  # Basic mangling
        f"__Z{len(func_name)}{func_name}",  # With prefix
    ]
    
    for variant in mangled_variants:
        sym = project.loader.find_symbol(variant)
        if sym:
            logger.info(f"Found function '{func_name}' (mangled as '{variant}') at {hex(sym.rebased_addr)}")
            return sym.rebased_addr
    
    logger.warning(f"Function '{func_name}' not found in binary")
    return None


def list_all_functions(project: angr.Project) -> list:
    """
    List all functions found in the binary.
    
    Args:
        project: The angr project
        
    Returns:
        List of function names and addresses
    """
    functions = []
    
    # Get from symbol table
    for sym in project.loader.main_object.symbols:
        if sym.is_function:
            functions.append({
                "name": sym.name,
                "address": hex(sym.rebased_addr),
                "size": sym.size if hasattr(sym, 'size') else None,
            })
    
    # Try CFG analysis for more functions
    try:
        cfg = project.analyses.CFGFast()
        for func_addr, func in cfg.kb.functions.items():
            if func.name not in [f["name"] for f in functions]:
                functions.append({
                    "name": func.name,
                    "address": hex(func_addr),
                    "size": func.size,
                })
    except Exception as e:
        logger.warning(f"CFG analysis failed: {e}")
    
    return functions
