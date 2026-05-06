"""
Bounded Execution Engine Module

Performs symbolic execution with loop bounding to prevent infinite paths.
Uses angr's LoopSeer exploration technique for efficient analysis.

Key Features:
- Bounded loop iteration
- Path explosion management
- Timeout handling
- Detailed execution statistics
"""

import angr
import logging
from angr.exploration_techniques import LoopSeer, DFS, Timeout
from typing import List, Optional, Any

logger = logging.getLogger(__name__)


class ExecutionError(Exception):
    """Raised when symbolic execution fails."""
    pass


def run_bounded_execution(
    project: angr.Project,
    state: angr.SimState,
    loop_bound: int = 5,
    timeout_seconds: Optional[int] = 300,
    max_steps: Optional[int] = 1000,
    use_dfs: bool = True,
) -> List[angr.SimState]:
    """
    Execute symbolic analysis with bounded loops.
    
    Args:
        project: The angr project
        state: Initial symbolic state
        loop_bound: Maximum loop iterations (default: 5)
        timeout_seconds: Execution timeout in seconds (default: 300)
        max_steps: Maximum number of execution steps (default: 1000)
        use_dfs: Use depth-first search (default: True)
        
    Returns:
        List of deadended (completed) states
        
    Raises:
        ExecutionError: If execution fails
        
    Example:
        >>> state = proj.factory.call_state(addr, arg1, arg2)
        >>> final_states = run_bounded_execution(proj, state, loop_bound=3)
        >>> for s in final_states:
        ...     print(f"Return value: {s.regs.rax}")
    
    Notes:
        - LoopSeer prevents infinite loops by bounding iterations
        - Paths exceeding the bound are discarded
        - This addresses the halting problem practically
    """
    logger.info("Starting bounded symbolic execution")
    logger.info(f"Loop bound: {loop_bound}, Timeout: {timeout_seconds}s, Max steps: {max_steps}")
    
    # Create simulation manager
    simgr = project.factory.simgr(state)
    logger.info("Created simulation manager")
    
    # Apply exploration techniques
    
    # 1. LoopSeer: Bound loop iterations
    # - 'bound': Maximum iterations per loop
    # - 'limit_concrete_loops': Whether to limit loops with concrete bounds
    loop_seer = LoopSeer(
        bound=loop_bound,
        limit_concrete_loops=True,
        discard_stash='spinning'  # Discard states that exceed bound
    )
    simgr.use_technique(loop_seer)
    logger.info(f"Applied LoopSeer (bound={loop_bound})")
    
    # 2. DFS: Depth-first search for better path coverage
    if use_dfs:
        simgr.use_technique(DFS())
        logger.info("Applied DFS exploration")
    
    # 3. Timeout: Hard execution timeout
    if timeout_seconds:
        timeout_tech = Timeout(timeout_seconds)
        simgr.use_technique(timeout_tech)
        logger.info(f"Applied timeout ({timeout_seconds}s)")
    
    # Configure execution options
    exploration_options = {}
    if max_steps:
        exploration_options['n'] = max_steps
    
    try:
        # Run until all paths finish or timeout
        logger.info("Running symbolic execution...")
        
        if max_steps:
            simgr.run(**exploration_options)
        else:
            simgr.run()
        
        logger.info("Execution completed")
        
        # Report statistics
        stats = {
            "deadended": len(simgr.deadended),
            "active": len(simgr.active),
            "errored": len(simgr.errored),
            "spinning": len(simgr.spinning) if 'spinning' in simgr.stashes else 0,
            "unconstrained": len(simgr.unconstrained),
        }
        
        logger.info(f"Execution statistics: {stats}")
        
        # Log errors if any
        if simgr.errored:
            logger.warning(f"Found {len(simgr.errored)} errored states")
            for err_state in simgr.errored[:3]:  # Log first 3
                logger.warning(f"Error: {err_state.error}")
        
        # Return completed states
        return simgr.deadended
        
    except Exception as e:
        error_msg = f"Symbolic execution failed: {str(e)}"
        logger.error(error_msg)
        
        # Try to save partial results
        if hasattr(simgr, 'deadended') and simgr.deadended:
            logger.warning(f"Returning {len(simgr.deadended)} partial results")
            return simgr.deadended
        
        raise ExecutionError(error_msg)


def run_execution_with_hooks(
    project: angr.Project,
    state: angr.SimState,
    hooks: dict,
    loop_bound: int = 5,
    timeout_seconds: Optional[int] = 300,
) -> List[angr.SimState]:
    """
    Run execution with custom function hooks.
    
    Hooks allow you to override external functions or model
    system calls that angr cannot handle natively.
    
    Args:
        project: The angr project
        state: Initial symbolic state
        hooks: Dictionary mapping addresses to hook functions
        loop_bound: Maximum loop iterations
        timeout_seconds: Execution timeout
        
    Returns:
        List of deadended states
        
    Example:
        >>> def mock_malloc(state):
        ...     size = state.regs.rdi
        ...     addr = state.heap.allocate(size)
        ...     state.regs.rax = addr
        ...     return
        >>> hooks = {0x401000: mock_malloc}
        >>> states = run_execution_with_hooks(proj, state, hooks)
    """
    # Apply hooks
    for addr, hook_func in hooks.items():
        project.hook(addr, hook_func)
        logger.info(f"Hooked address {hex(addr)}")
    
    # Run execution
    return run_bounded_execution(
        project,
        state,
        loop_bound=loop_bound,
        timeout_seconds=timeout_seconds
    )


def extract_execution_trace(state: angr.SimState) -> List[int]:
    """
    Extract the execution trace (addresses visited) from a state.
    
    Args:
        state: The symbolic state
        
    Returns:
        List of instruction addresses in execution order
    """
    if hasattr(state, 'history') and hasattr(state.history, 'bbl_addrs'):
        trace = list(state.history.bbl_addrs)
        logger.debug(f"Extracted trace with {len(trace)} basic blocks")
        return trace
    else:
        logger.warning("State has no execution trace")
        return []


def get_path_constraints(state: angr.SimState) -> List[Any]:
    """
    Get all path constraints from a state.
    
    Args:
        state: The symbolic state
        
    Returns:
        List of constraint expressions
    """
    constraints = state.solver.constraints
    logger.debug(f"State has {len(constraints)} constraints")
    return constraints


def check_state_satisfiability(state: angr.SimState) -> bool:
    """
    Check if a state's constraints are satisfiable.
    
    Args:
        state: The symbolic state
        
    Returns:
        True if satisfiable, False if UNSAT
    """
    satisfiable = state.solver.satisfiable()
    logger.debug(f"State satisfiability: {satisfiable}")
    return satisfiable
