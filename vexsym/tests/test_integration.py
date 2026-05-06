"""
Integration test: Complete verification workflow.
"""

import pytest
import tempfile
import os
from vexsym.core import (
    compile_source,
    load_projects,
    create_entangled_states,
    run_bounded_execution,
    compare_results,
)


def test_equivalent_functions():
    """
    Test that two identical functions are detected as equivalent.
    """
    original_code = """
    int compute(int x, int y) {
        if (x > y) {
            return x - y;
        } else {
            return y - x;
        }
    }
    
    int main() {
        return compute(10, 5);
    }
    """
    
    decompiled_code = """
    int compute(int x, int y) {
        if (x > y) {
            return x - y;
        } else {
            return y - x;
        }
    }
    
    int main() {
        return compute(10, 5);
    }
    """
    
    try:
        # Compile both
        orig_bin = compile_source(original_code, is_cpp=False)
        dec_bin = compile_source(decompiled_code, is_cpp=False)
        
        # Load projects
        proj_o, proj_d = load_projects(orig_bin, dec_bin)
        
        # Create entangled states
        state_o, state_d, args = create_entangled_states(
            proj_o, proj_d, "compute", num_args=2
        )
        
        # Run execution
        states_o = run_bounded_execution(proj_o, state_o, loop_bound=3, timeout_seconds=30)
        states_d = run_bounded_execution(proj_d, state_d, loop_bound=3, timeout_seconds=30)
        
        # Compare
        result = compare_results(states_o, states_d, args)
        
        assert result.equivalent is True
        assert len(result.divergences) == 0
        
    finally:
        for path in [orig_bin, dec_bin]:
            if os.path.exists(path):
                os.remove(path)


def test_divergent_functions():
    """
    Test that two different functions are detected as divergent.
    """
    original_code = """
    int compute(int x) {
        if (x > 10) {
            return x * 2;
        }
        return x;
    }
    
    int main() {
        return compute(15);
    }
    """
    
    # Decompiled version has bug: missing the multiplication
    decompiled_code = """
    int compute(int x) {
        if (x > 10) {
            return x;  // BUG: Should be x * 2
        }
        return x;
    }
    
    int main() {
        return compute(15);
    }
    """
    
    try:
        # Compile both
        orig_bin = compile_source(original_code, is_cpp=False)
        dec_bin = compile_source(decompiled_code, is_cpp=False)
        
        # Load projects
        proj_o, proj_d = load_projects(orig_bin, dec_bin)
        
        # Create entangled states
        state_o, state_d, args = create_entangled_states(
            proj_o, proj_d, "compute", num_args=1
        )
        
        # Run execution
        states_o = run_bounded_execution(proj_o, state_o, loop_bound=3, timeout_seconds=30)
        states_d = run_bounded_execution(proj_d, state_d, loop_bound=3, timeout_seconds=30)
        
        # Compare
        result = compare_results(states_o, states_d, args)
        
        # Should find divergence
        assert result.equivalent is False
        assert len(result.divergences) > 0
        
        # Check that the counterexample is for x > 10
        div = result.divergences[0]
        assert div["type"] == "return_value_mismatch"
        
    finally:
        for path in [orig_bin, dec_bin]:
            if os.path.exists(path):
                os.remove(path)


def test_missing_branch():
    """
    Test detection of missing branch (the D-Helix failure case).
    """
    original_code = """
    int check_access(int admin) {
        if (admin == 1) {
            return 100;  // Grant access
        }
        return 0;  // Deny access
    }
    
    int main() {
        return check_access(1);
    }
    """
    
    # Decompiler removed the security check
    decompiled_code = """
    int check_access(int admin) {
        return 100;  // Always grant access - SECURITY BUG!
    }
    
    int main() {
        return check_access(1);
    }
    """
    
    try:
        # Compile both
        orig_bin = compile_source(original_code, is_cpp=False)
        dec_bin = compile_source(decompiled_code, is_cpp=False)
        
        # Load projects
        proj_o, proj_d = load_projects(orig_bin, dec_bin)
        
        # Create entangled states
        state_o, state_d, args = create_entangled_states(
            proj_o, proj_d, "check_access", num_args=1
        )
        
        # Run execution
        states_o = run_bounded_execution(proj_o, state_o, loop_bound=3, timeout_seconds=30)
        states_d = run_bounded_execution(proj_d, state_d, loop_bound=3, timeout_seconds=30)
        
        # Compare
        result = compare_results(states_o, states_d, args)
        
        # Should detect that for admin != 1, outputs differ
        assert result.equivalent is False
        assert len(result.divergences) > 0
        
    finally:
        for path in [orig_bin, dec_bin]:
            if os.path.exists(path):
                os.remove(path)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
