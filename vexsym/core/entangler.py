"""
State Entangler Module

Creates synchronized symbolic execution states for both binaries
with shared symbolic variables, enabling relational verification.

Key Features:
- Shared symbolic arguments across both programs
- C++ object handling with 'this' pointer
- Virtual table (vtable) support
- Memory synchronization for pointer arguments
- C++ name mangling support via cxxfilt
"""

import angr
import claripy
import logging
import re
from typing import Tuple, List, Optional, Dict, Any

# Try to import cxxfilt for C++ name demangling
try:
    import cxxfilt
    HAS_CXXFILT = True
except ImportError:
    HAS_CXXFILT = False

logger = logging.getLogger(__name__)


class EntanglementError(Exception):
    """Raised when state entanglement fails."""
    pass


# =============================================================================
# C++ NAME MANGLING SUPPORT
# =============================================================================

def is_cpp_mangled_name(name: str) -> bool:
    """Check if a name appears to be a C++ mangled name."""
    return name.startswith('_Z') or name.startswith('__Z')


def demangle_cpp_name(name: str) -> str:
    """Demangle a C++ mangled name to get the base function name."""
    if not HAS_CXXFILT:
        return name
    try:
        demangled = cxxfilt.demangle(name)
        # Extract just the function name without parameters
        # e.g., "func0(float)" -> "func0"
        if '(' in demangled:
            demangled = demangled.split('(')[0]
        # Replace :: with _ for class methods
        demangled = demangled.replace('::', '_')
        return demangled
    except:
        return name


def find_function_symbol(project: angr.Project, func_name: str) -> Optional[Any]:
    """
    Find a function symbol in the binary, handling various naming conventions.
    
    Tries multiple strategies:
    1. Direct symbol lookup
    2. Underscore prefixes (_func, __func)
    3. C++ name mangling via cxxfilt
    4. Suffix matching (for funcN patterns)
    5. FUN_/sub_ prefixes (Ghidra/IDA style)
    6. CFG-based function discovery
    
    Args:
        project: The angr project
        func_name: Function name to search for (e.g., 'func0', 'myFunction', 'main')
        
    Returns:
        Symbol object if found, None otherwise
    """
    # Normalize the function name (remove leading underscores for comparison)
    func_name_normalized = func_name.lstrip('_')
    
    # Strategy 1: Direct lookup
    sym = project.loader.find_symbol(func_name)
    if sym:
        logger.info(f"Found symbol '{func_name}' directly at {hex(sym.rebased_addr)}")
        return sym
    
    # Strategy 1b: Try with underscore prefix (common in some binaries)
    for prefix in ['_', '__']:
        sym = project.loader.find_symbol(prefix + func_name)
        if sym:
            logger.info(f"Found symbol '{prefix}{func_name}' at {hex(sym.rebased_addr)}")
            return sym
    
    # Strategy 2: Search all symbols for matching mangled name or pattern
    for sym in project.loader.symbols:
        if not sym.name:
            continue
        
        sym_name_normalized = sym.name.lstrip('_')
            
        # Check if this is the mangled version of our function
        if is_cpp_mangled_name(sym.name):
            demangled = demangle_cpp_name(sym.name)
            demangled_normalized = demangled.lstrip('_')
            if (demangled == func_name or 
                demangled_normalized == func_name_normalized or
                demangled.endswith(f"_{func_name}") or 
                demangled.endswith(func_name) or
                demangled_normalized.endswith(func_name_normalized)):
                logger.info(f"Found mangled symbol '{sym.name}' -> '{demangled}' at {hex(sym.rebased_addr)}")
                return sym
        
        # Check exact match or suffix match (handles funcN, func_N, etc.)
        if (sym.name == func_name or 
            sym_name_normalized == func_name_normalized or
            sym.name.endswith(func_name) or
            sym_name_normalized.endswith(func_name_normalized)):
            logger.info(f"Found symbol '{sym.name}' at {hex(sym.rebased_addr)}")
            return sym
    
    # Strategy 3: Handle FUN_/sub_ prefixes (Ghidra/IDA naming)
    if "FUN_" in func_name:
        match = re.search(r"FUN_([0-9a-fA-F]+)", func_name)
        if match:
            addr = int(match.group(1), 16)
            logger.info(f"Parsed FUN_ address: {hex(addr)}")
            return type('Symbol', (), {'rebased_addr': addr, 'name': func_name})()
    
    if "sub_" in func_name:
        match = re.search(r"sub_([0-9a-fA-F]+)", func_name)
        if match:
            addr = int(match.group(1), 16)
            logger.info(f"Parsed sub_ address: {hex(addr)}")
            return type('Symbol', (), {'rebased_addr': addr, 'name': func_name})()
    
    # Strategy 4: Try to find function by CFG analysis
    try:
        cfg = project.analyses.CFGFast()
        for func_addr, func in cfg.kb.functions.items():
            if func.name:
                cfg_name_normalized = func.name.lstrip('_')
                if (func.name == func_name or 
                    cfg_name_normalized == func_name_normalized or
                    func.name.endswith(func_name) or
                    cfg_name_normalized.endswith(func_name_normalized)):
                    logger.info(f"Found function '{func.name}' via CFG at {hex(func_addr)}")
                    return type('Symbol', (), {'rebased_addr': func_addr, 'name': func.name})()
    except Exception as e:
        logger.debug(f"CFG analysis for function lookup failed: {e}")
    
    return None


def create_entangled_states(
    proj_orig: angr.Project,
    proj_dec: angr.Project,
    func_name_orig: str,
    func_name_dec: Optional[str] = None,
    arg_types: Optional[List[str]] = None,
    num_args: int = 3,
) -> Tuple[angr.SimState, angr.SimState, List[claripy.ast.BV]]:
    """
    Create entangled symbolic states for C/C++ function verification.
    
    Both states share the same symbolic variables, ensuring that
    the SMT solver can find inputs that trigger divergent behavior.
    
    Supports C++ name mangling - will search for mangled versions of
    the function name if the direct lookup fails.
    
    Args:
        proj_orig: The original binary project
        proj_dec: The decompiled binary project
        func_name_orig: Function name in original binary
        func_name_dec: Function name in decompiled binary (defaults to func_name_orig)
        arg_types: List of argument types (e.g., ['int64', 'ptr', 'int32'])
        num_args: Number of arguments if arg_types not specified
        
    Returns:
        Tuple of (state_orig, state_dec, symbolic_args)
        
    Raises:
        EntanglementError: If function not found or state creation fails
    """
    if func_name_dec is None:
        func_name_dec = func_name_orig
    
    # Locate functions using mangling-aware search
    sym_orig = find_function_symbol(proj_orig, func_name_orig)
    sym_dec = find_function_symbol(proj_dec, func_name_dec)
    
    if not sym_orig:
        # List available symbols for debugging (show function symbols, not just 'func')
        available_funcs = [s.name for s in proj_orig.loader.symbols 
                          if s.name and s.is_function][:20]
        # Also try CFG
        try:
            cfg = proj_orig.analyses.CFGFast()
            cfg_funcs = [f.name for f in cfg.kb.functions.values() if f.name][:20]
        except:
            cfg_funcs = []
        raise EntanglementError(
            f"Function '{func_name_orig}' not found in original binary. "
            f"Available symbols: {available_funcs}. CFG functions: {cfg_funcs}"
        )
    
    if not sym_dec:
        # List available symbols for debugging (show function symbols, not just 'func')
        available_funcs = [s.name for s in proj_dec.loader.symbols 
                          if s.name and s.is_function][:20]
        # Also try CFG
        try:
            cfg = proj_dec.analyses.CFGFast()
            cfg_funcs = [f.name for f in cfg.kb.functions.values() if f.name][:20]
        except:
            cfg_funcs = []
        raise EntanglementError(
            f"Function '{func_name_dec}' not found in decompiled binary. "
            f"Available symbols: {available_funcs}. CFG functions: {cfg_funcs}"
        )
    
    logger.info(f"Original function at: {hex(sym_orig.rebased_addr)}")
    logger.info(f"Decompiled function at: {hex(sym_dec.rebased_addr)}")
    
    # Determine architecture
    is_x64 = proj_orig.arch.bits == 64
    bit_width = 64 if is_x64 else 32
    
    # Create shared symbolic arguments
    symbolic_args = []
    
    if arg_types:
        # Create typed arguments
        for i, arg_type in enumerate(arg_types):
            if arg_type in ['int64', 'long', 'uint64', 'ulong']:
                symbolic_args.append(claripy.BVS(f"arg{i}", 64))
            elif arg_type in ['int32', 'int', 'uint32', 'uint']:
                symbolic_args.append(claripy.BVS(f"arg{i}", 32))
            elif arg_type in ['ptr', 'pointer']:
                symbolic_args.append(claripy.BVS(f"arg{i}_ptr", bit_width))
            elif arg_type in ['int16', 'short', 'uint16', 'ushort']:
                symbolic_args.append(claripy.BVS(f"arg{i}", 16))
            elif arg_type in ['int8', 'char', 'uint8', 'uchar']:
                symbolic_args.append(claripy.BVS(f"arg{i}", 8))
            else:
                logger.warning(f"Unknown type '{arg_type}', defaulting to {bit_width}-bit")
                symbolic_args.append(claripy.BVS(f"arg{i}", bit_width))
    else:
        # Create default-sized arguments
        for i in range(num_args):
            symbolic_args.append(claripy.BVS(f"arg{i}", bit_width))
    
    logger.info(f"Created {len(symbolic_args)} shared symbolic arguments")
    
    try:
        # Initialize states with shared symbolic arguments
        # call_state automatically sets up calling convention (registers/stack)
        state_orig = proj_orig.factory.call_state(
            sym_orig.rebased_addr,
            *symbolic_args,
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            }
        )
        logger.info("Created original state")
        
        state_dec = proj_dec.factory.call_state(
            sym_dec.rebased_addr,
            *symbolic_args,
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            }
        )
        logger.info("Created decompiled state")
        
    except Exception as e:
        raise EntanglementError(f"Failed to create entangled states: {str(e)}")
    
    return state_orig, state_dec, symbolic_args


def setup_cpp_state(
    state: angr.SimState,
    obj_size: int = 256,
    is_x64: bool = True,
) -> Tuple[int, claripy.ast.BV]:
    """
    Set up C++ object state with 'this' pointer.
    
    Creates a symbolic memory region representing a class instance
    and injects the 'this' pointer into the appropriate register.
    
    Args:
        state: The symbolic state to configure
        obj_size: Size of the object in bytes (default: 256)
        is_x64: Whether the architecture is 64-bit
        
    Returns:
        Tuple of (this_pointer_address, symbolic_memory)
        
    Example:
        >>> state = proj.factory.call_state(addr)
        >>> this_ptr, mem = setup_cpp_state(state)
        >>> # State now has 'this' pointer set up for method calls
    """
    logger.info(f"Setting up C++ object (size={obj_size} bytes)")
    
    # Allocate symbolic object in heap
    this_ptr = state.heap.allocate(obj_size)
    logger.info(f"Allocated object at address: {hex(this_ptr)}")
    
    # Symbolize the object's memory
    # This ensures that reading `this->member` returns a symbolic variable
    sym_mem = claripy.BVS("this_obj_mem", obj_size * 8)
    state.memory.store(this_ptr, sym_mem)
    logger.info("Symbolized object memory")
    
    # Inject 'this' pointer into the correct register
    # x64 System V ABI: first arg (this) is in RDI
    # x86: first arg (this) is on stack
    if is_x64:
        state.regs.rdi = this_ptr
        logger.info(f"Set RDI = {hex(this_ptr)} (this pointer)")
    else:
        # For x86, 'this' is the first stack argument
        # ESP points to return address, ESP+4 is first arg
        state.memory.store(
            state.regs.esp + 4,
            claripy.BVV(this_ptr, 32),
            endness=state.arch.memory_endness
        )
        logger.info(f"Set [ESP+4] = {hex(this_ptr)} (this pointer)")
    
    return this_ptr, sym_mem


def setup_cpp_vtable(
    state: angr.SimState,
    this_ptr: int,
    vtable_addr: int,
) -> None:
    """
    Set up virtual table pointer for C++ objects.
    
    By default, the vtable pointer is symbolic. This can cause
    symbolic jumps. If you know the vtable address from the
    original binary, you can constrain it to be concrete.
    
    Args:
        state: The symbolic state
        this_ptr: Address of the 'this' pointer
        vtable_addr: Address of the vtable in the binary
        
    Example:
        >>> this_ptr, mem = setup_cpp_state(state)
        >>> vtable = proj.loader.find_symbol("_ZTV9MyClass")
        >>> setup_cpp_vtable(state, this_ptr, vtable.rebased_addr + 16)
    """
    logger.info(f"Setting vtable pointer at {hex(this_ptr)} to {hex(vtable_addr)}")
    
    # Vtable pointer is typically at offset 0 of the object
    bit_width = state.arch.bits
    state.memory.store(
        this_ptr,
        claripy.BVV(vtable_addr, bit_width),
        endness=state.arch.memory_endness
    )


def create_shared_memory_buffer(
    state_orig: angr.SimState,
    state_dec: angr.SimState,
    buffer_size: int,
) -> Tuple[int, int, claripy.ast.BV]:
    """
    Create a shared symbolic memory buffer for both states.
    
    Useful when the function takes a pointer to a buffer that
    should contain the same symbolic data in both executions.
    
    Args:
        state_orig: Original state
        state_dec: Decompiled state
        buffer_size: Size of buffer in bytes
        
    Returns:
        Tuple of (orig_buffer_addr, dec_buffer_addr, symbolic_data)
        
    Example:
        >>> addr_o, addr_d, data = create_shared_memory_buffer(s_o, s_d, 64)
        >>> # Pass addr_o and addr_d as arguments to respective functions
    """
    logger.info(f"Creating shared symbolic buffer (size={buffer_size} bytes)")
    
    # Allocate buffers in both heaps
    buf_orig = state_orig.heap.allocate(buffer_size)
    buf_dec = state_dec.heap.allocate(buffer_size)
    
    # Create shared symbolic data
    sym_data = claripy.BVS("shared_buffer", buffer_size * 8)
    
    # Store the same symbolic data in both buffers
    state_orig.memory.store(buf_orig, sym_data)
    state_dec.memory.store(buf_dec, sym_data)
    
    logger.info(f"Original buffer at: {hex(buf_orig)}")
    logger.info(f"Decompiled buffer at: {hex(buf_dec)}")
    
    return buf_orig, buf_dec, sym_data


def add_memory_constraints(
    state: angr.SimState,
    constraints: List[Any],
) -> None:
    """
    Add custom constraints to a state.
    
    Useful for restricting input ranges or relationships.
    
    Args:
        state: The symbolic state
        constraints: List of claripy expressions
        
    Example:
        >>> # Constrain arg to be positive
        >>> add_memory_constraints(state, [args[0] > 0])
    """
    for constraint in constraints:
        state.solver.add(constraint)
        logger.debug(f"Added constraint: {constraint}")
