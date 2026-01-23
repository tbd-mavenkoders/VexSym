"""
VexHelix: Bounded Relational Symbolic Execution for Decompilation Verification

A robust automated system for verifying semantic equivalence between
original binaries and decompiled source code using VEX IR and angr.
"""

__version__ = "1.0.0"
__author__ = "VexHelix Project"

from .core.compiler import compile_source
from .core.loader import load_projects
from .core.entangler import create_entangled_states, setup_cpp_state
from .core.executor import run_bounded_execution
from .core.comparator import compare_results

__all__ = [
    "compile_source",
    "load_projects",
    "create_entangled_states",
    "setup_cpp_state",
    "run_bounded_execution",
    "compare_results",
]
