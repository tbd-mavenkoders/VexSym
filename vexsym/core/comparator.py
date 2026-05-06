"""
Comparator Module

Compares final states from both executions to detect semantic discrepancies.
Uses SMT solving to find concrete inputs that trigger different behaviors.

Key Features:
- Cartesian product comparison
- Return value comparison
- Memory comparison for side effects
- Concrete counterexample generation
"""

import claripy
import angr
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class ComparisonResult:
    """
    Result of a comparison between original and decompiled execution.
    """
    def __init__(self):
        self.equivalent = True
        self.divergences = []
        self.statistics = {
            "states_orig": 0,
            "states_dec": 0,
            "comparisons_attempted": 0,
            "path_pairs_compatible": 0,
        }
    
    def add_divergence(self, divergence: Dict[str, Any]):
        """Add a detected divergence."""
        self.equivalent = False
        self.divergences.append(divergence)
    
    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            "equivalent": self.equivalent,
            "divergences": self.divergences,
            "statistics": self.statistics,
        }


def compare_results(
    states_orig: List[angr.SimState],
    states_dec: List[angr.SimState],
    input_vars: List[claripy.ast.BV],
    compare_memory: bool = False,
    memory_regions: Optional[List[tuple]] = None,
) -> ComparisonResult:
    """
    Compare final states to find semantic discrepancies.
    
    Performs Cartesian product comparison: each path from the original
    is compared with each path from the decompiled version. For compatible
    paths (non-contradicting constraints), we check if outputs differ.
    
    Args:
        states_orig: Final states from original binary
        states_dec: Final states from decompiled binary
        input_vars: The shared symbolic input variables
        compare_memory: Whether to compare memory side effects
        memory_regions: List of (address, size) tuples to compare
        
    Returns:
        ComparisonResult object with all divergences found
        
    Example:
        >>> result = compare_results(simgr_o.deadended, simgr_d.deadended, args)
        >>> if not result.equivalent:
        ...     for div in result.divergences:
        ...         print(f"Input: {div['inputs']}")
        ...         print(f"Original output: {div['orig_output']}")
        ...         print(f"Decompiled output: {div['dec_output']}")
    """
    logger.info("Starting result comparison")
    logger.info(f"Original states: {len(states_orig)}, Decompiled states: {len(states_dec)}")
    
    result = ComparisonResult()
    result.statistics["states_orig"] = len(states_orig)
    result.statistics["states_dec"] = len(states_dec)
    
    # Handle empty state sets
    if not states_orig and not states_dec:
        logger.warning("Both executions produced no final states")
        return result
    
    if not states_orig:
        logger.warning("Original execution produced no states")
        result.add_divergence({
            "type": "no_original_states",
            "message": "Original binary produced no final states (possible crash or infinite loop)"
        })
        return result
    
    if not states_dec:
        logger.warning("Decompiled execution produced no states")
        result.add_divergence({
            "type": "no_decompiled_states",
            "message": "Decompiled binary produced no final states (possible crash or infinite loop)"
        })
        return result
    
    # Cartesian product comparison
    for i, state_o in enumerate(states_orig):
        for j, state_d in enumerate(states_dec):
            result.statistics["comparisons_attempted"] += 1
            
            logger.debug(f"Comparing original state {i} with decompiled state {j}")
            
            # Check path compatibility
            divergence = _compare_state_pair(
                state_o,
                state_d,
                input_vars,
                compare_memory,
                memory_regions
            )
            
            if divergence:
                result.statistics["path_pairs_compatible"] += 1
                
                if divergence.get("has_divergence"):
                    result.add_divergence(divergence)
                    logger.warning(f"Found divergence: {divergence['type']}")
                    
                    # Optimization: Return immediately on first divergence
                    # or continue to find all? User preference.
                    # For now, continue to collect all divergences
    
    if result.equivalent:
        logger.info("No divergences found - programs appear equivalent within bounds")
    else:
        logger.warning(f"Found {len(result.divergences)} divergence(s)")
    
    return result


def _compare_state_pair(
    state_o: angr.SimState,
    state_d: angr.SimState,
    input_vars: List[claripy.ast.BV],
    compare_memory: bool,
    memory_regions: Optional[List[tuple]],
) -> Optional[Dict[str, Any]]:
    """
    Compare a single pair of states.
    
    Returns:
        Divergence dictionary if discrepancy found, None if paths incompatible
    """
    # Create combined solver with constraints from BOTH paths
    combined_solver = claripy.Solver()
    
    try:
        # Add constraints from original path
        for constraint in state_o.solver.constraints:
            combined_solver.add(constraint)
        
        # Add constraints from decompiled path
        for constraint in state_d.solver.constraints:
            combined_solver.add(constraint)
        
    except Exception as e:
        logger.error(f"Failed to merge constraints: {e}")
        return None
    
    # Check if this combination is feasible
    if not combined_solver.satisfiable():
        # These paths cannot happen simultaneously
        logger.debug("Paths incompatible (contradicting constraints)")
        return None
    
    # Paths are compatible - now check if outputs differ
    
    # 1. Compare return values (RAX/EAX register)
    ret_o = state_o.regs.rax if state_o.arch.bits == 64 else state_o.regs.eax
    ret_d = state_d.regs.rax if state_d.arch.bits == 64 else state_d.regs.eax
    
    # Add constraint: RetO != RetD
    combined_solver.add(ret_o != ret_d)
    
    if combined_solver.satisfiable():
        # DIVERGENCE FOUND!
        return _create_divergence_report(
            "return_value_mismatch",
            combined_solver,
            input_vars,
            ret_o,
            ret_d,
            state_o,
            state_d
        )
    
    # 2. If return values are the same, check memory (if requested)
    if compare_memory and memory_regions:
        memory_divergence = _compare_memory_regions(
            state_o,
            state_d,
            memory_regions,
            combined_solver,
            input_vars
        )
        
        if memory_divergence:
            return memory_divergence
    
    # No divergence found for this path pair
    return {"has_divergence": False}


def _create_divergence_report(
    divergence_type: str,
    solver: claripy.Solver,
    input_vars: List[claripy.ast.BV],
    ret_o: Any,
    ret_d: Any,
    state_o: angr.SimState,
    state_d: angr.SimState,
) -> Dict[str, Any]:
    """
    Create a detailed divergence report with concrete values.
    """
    logger.info(f"Creating divergence report for type: {divergence_type}")
    
    # Evaluate input variables to get concrete counterexample
    concrete_inputs = []
    for var in input_vars:
        try:
            # Get one satisfying value
            val = solver.eval(var, 1)[0]
            
            # Convert to signed if it's a bitvector
            signed_val = val
            if val > (1 << (var.size() - 1)):
                signed_val = val - (1 << var.size())
            
            concrete_inputs.append({
                "name": str(var),
                "value": val,
                "hex": hex(val),
                "signed": signed_val,
            })
        except Exception as e:
            logger.error(f"Failed to evaluate input variable {var}: {e}")
            concrete_inputs.append({
                "name": str(var),
                "value": "error",
                "error": str(e)
            })
    
    # Evaluate outputs
    try:
        orig_output = solver.eval(ret_o, 1)[0]
        dec_output = solver.eval(ret_d, 1)[0]
    except Exception as e:
        logger.error(f"Failed to evaluate outputs: {e}")
        orig_output = str(ret_o)
        dec_output = str(ret_d)
    
    # Extract execution traces if available
    trace_o = []
    trace_d = []
    
    if hasattr(state_o, 'history') and hasattr(state_o.history, 'bbl_addrs'):
        trace_o = [hex(addr) for addr in list(state_o.history.bbl_addrs)[-10:]]  # Last 10
    
    if hasattr(state_d, 'history') and hasattr(state_d.history, 'bbl_addrs'):
        trace_d = [hex(addr) for addr in list(state_d.history.bbl_addrs)[-10:]]
    
    report = {
        "has_divergence": True,
        "type": divergence_type,
        "inputs": concrete_inputs,
        "orig_output": {
            "value": orig_output,
            "hex": hex(orig_output) if isinstance(orig_output, int) else str(orig_output),
        },
        "dec_output": {
            "value": dec_output,
            "hex": hex(dec_output) if isinstance(dec_output, int) else str(dec_output),
        },
        "execution_traces": {
            "original": trace_o,
            "decompiled": trace_d,
        }
    }
    
    return report


def _compare_memory_regions(
    state_o: angr.SimState,
    state_d: angr.SimState,
    memory_regions: List[tuple],
    combined_solver: claripy.Solver,
    input_vars: List[claripy.ast.BV],
) -> Optional[Dict[str, Any]]:
    """
    Compare memory regions for side effects.
    
    Args:
        state_o: Original state
        state_d: Decompiled state
        memory_regions: List of (address, size) tuples
        combined_solver: Merged constraint solver
        input_vars: Input variables for counterexample
        
    Returns:
        Divergence report if memory differs, None otherwise
    """
    logger.debug(f"Comparing {len(memory_regions)} memory regions")
    
    for addr, size in memory_regions:
        try:
            # Load memory from both states
            mem_o = state_o.memory.load(addr, size)
            mem_d = state_d.memory.load(addr, size)
            
            # Check if they can differ
            test_solver = combined_solver.branch()
            test_solver.add(mem_o != mem_d)
            
            if test_solver.satisfiable():
                logger.warning(f"Memory divergence at {hex(addr)}")
                
                # Create divergence report
                return _create_divergence_report(
                    "memory_mismatch",
                    test_solver,
                    input_vars,
                    mem_o,
                    mem_d,
                    state_o,
                    state_d
                )
        
        except Exception as e:
            logger.error(f"Failed to compare memory at {hex(addr)}: {e}")
            continue
    
    return None


def quick_check_equivalence(
    states_orig: List[angr.SimState],
    states_dec: List[angr.SimState],
) -> bool:
    """
    Quick equivalence check without detailed analysis.
    
    Returns True if outputs appear equivalent, False otherwise.
    Useful for fast preliminary checks.
    
    Args:
        states_orig: Original states
        states_dec: Decompiled states
        
    Returns:
        True if likely equivalent, False if divergence detected
    """
    if len(states_orig) != len(states_dec):
        return False
    
    # Simple heuristic: check if return values can be equal
    for state_o, state_d in zip(states_orig, states_dec):
        ret_o = state_o.regs.rax if state_o.arch.bits == 64 else state_o.regs.eax
        ret_d = state_d.regs.rax if state_d.arch.bits == 64 else state_d.regs.eax
        
        # Can they ever be equal?
        test_solver = claripy.Solver()
        test_solver.add(state_o.solver.constraints)
        test_solver.add(state_d.solver.constraints)
        test_solver.add(ret_o == ret_d)
        
        if not test_solver.satisfiable():
            return False  # They're always different
    
    return True  # Possibly equivalent
