"""
Tests for the compiler module.
"""

import pytest
import tempfile
import os
from vexsym.core.compiler import (
    compile_source,
    CompilationError,
    verify_compiler_availability
)


def test_verify_compiler_availability():
    """Test compiler availability check."""
    result = verify_compiler_availability()
    
    assert "gcc_available" in result
    assert "gpp_available" in result
    
    # In our environment, compilers should be available
    assert result["gcc_available"] is True
    assert result["gpp_available"] is True


def test_compile_simple_c_code():
    """Test compiling simple C code."""
    code = """
    int add(int a, int b) {
        return a + b;
    }
    
    int main() {
        return add(5, 3);
    }
    """
    
    try:
        bin_path = compile_source(code, is_cpp=False)
        assert os.path.exists(bin_path)
        assert os.path.getsize(bin_path) > 0
    finally:
        if os.path.exists(bin_path):
            os.remove(bin_path)


def test_compile_simple_cpp_code():
    """Test compiling simple C++ code."""
    code = """
    #include <iostream>
    
    int multiply(int a, int b) {
        return a * b;
    }
    
    int main() {
        return multiply(4, 7);
    }
    """
    
    try:
        bin_path = compile_source(code, is_cpp=True)
        assert os.path.exists(bin_path)
        assert os.path.getsize(bin_path) > 0
    finally:
        if os.path.exists(bin_path):
            os.remove(bin_path)


def test_compile_with_error():
    """Test that compilation errors are properly caught."""
    code = """
    int main() {
        return undefined_function();  // This should fail
    }
    """
    
    with pytest.raises(CompilationError) as exc_info:
        compile_source(code, is_cpp=False)
    
    assert "Compilation failed" in str(exc_info.value)


def test_compile_with_syntax_error():
    """Test compilation with syntax error."""
    code = """
    int main() {
        return 42  // Missing semicolon
    }
    """
    
    with pytest.raises(CompilationError):
        compile_source(code, is_cpp=False)


def test_compile_with_custom_output_path():
    """Test compiling with custom output path."""
    code = """
    int main() {
        return 0;
    }
    """
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = os.path.join(tmpdir, "custom_binary")
        bin_path = compile_source(code, is_cpp=False, output_path=output_path)
        
        assert bin_path == output_path
        assert os.path.exists(bin_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
