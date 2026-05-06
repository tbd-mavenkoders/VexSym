"""
Example: Simple verification using VexSym API.

This example demonstrates verifying a simple decompiled function
against its original binary.
"""

import requests
import json


def verify_simple_function():
    """Verify a simple integer addition function."""
    
    # The decompiled code to verify
    decompiled_code = """
    int add(int a, int b) {
        return a + b;
    }
    
    int main() {
        return add(5, 3);
    }
    """
    
    # First, compile the original to create a binary
    # In a real scenario, you'd have the original binary
    import tempfile
    from vexsym.core import compile_source
    
    original_bin = compile_source(decompiled_code, is_cpp=False)
    
    # Prepare the API request
    with open(original_bin, 'rb') as f:
        files = {'original_binary': f}
        data = {
            'decompiled_code': decompiled_code,
            'language': 'c',
            'function_name': 'add',
            'num_args': 2,
            'loop_bound': 3,
            'timeout': 60
        }
        
        # Send request to API
        response = requests.post(
            'http://localhost:8000/verify',
            files=files,
            data=data
        )
    
    # Parse response
    result = response.json()
    
    print("Verification Result:")
    print(f"Status: {result['status']}")
    print(f"Equivalent: {result.get('equivalent', 'N/A')}")
    
    if result['status'] == 'different':
        print("\nDivergences found:")
        for div in result['divergences']:
            print(f"\nType: {div['type']}")
            print("Inputs that trigger divergence:")
            for inp in div['inputs']:
                print(f"  {inp['name']}: {inp['value']} ({inp['hex']})")
            print(f"Original output: {div['orig_output']['hex']}")
            print(f"Decompiled output: {div['dec_output']['hex']}")
    
    # Cleanup
    import os
    os.remove(original_bin)


def verify_with_bug():
    """Verify a function with a bug in the decompilation."""
    
    original_code = """
    int compute(int x) {
        if (x > 10) {
            return x * 2;
        }
        return x;
    }
    
    int main() {
        return compute(5);
    }
    """
    
    # Buggy decompiled version
    decompiled_code = """
    int compute(int x) {
        if (x > 10) {
            return x;  // BUG: Missing multiplication
        }
        return x;
    }
    
    int main() {
        return compute(5);
    }
    """
    
    from vexsym.core import compile_source
    import requests
    import os
    
    original_bin = compile_source(original_code, is_cpp=False)
    
    with open(original_bin, 'rb') as f:
        files = {'original_binary': f}
        data = {
            'decompiled_code': decompiled_code,
            'language': 'c',
            'function_name': 'compute',
            'num_args': 1,
            'loop_bound': 3,
            'timeout': 60
        }
        
        response = requests.post(
            'http://localhost:8000/verify',
            files=files,
            data=data
        )
    
    result = response.json()
    
    print("\n" + "="*60)
    print("Example: Buggy Decompilation")
    print("="*60)
    print(f"Status: {result['status']}")
    
    if result['status'] == 'different':
        print("\n✗ Decompilation is INCORRECT")
        print(f"Found {len(result['divergences'])} divergence(s)")
        
        for i, div in enumerate(result['divergences'], 1):
            print(f"\nDivergence #{i}:")
            print("Counterexample inputs:")
            for inp in div['inputs']:
                print(f"  x = {inp['value']}")
            print(f"Original returns: {div['orig_output']['value']}")
            print(f"Decompiled returns: {div['dec_output']['value']}")
    else:
        print("✓ Decompilation appears correct")
    
    os.remove(original_bin)


if __name__ == "__main__":
    print("VexSym API Example")
    print("Make sure the API server is running: uvicorn vexsym.api.server:app")
    print()
    
    # Example 1: Correct decompilation
    print("Example 1: Verifying correct decompilation")
    try:
        verify_simple_function()
    except requests.exceptions.ConnectionError:
        print("Error: API server not running. Start with: uvicorn vexsym.api.server:app")
    except Exception as e:
        print(f"Error: {e}")
    
    # Example 2: Buggy decompilation
    print("\nExample 2: Verifying buggy decompilation")
    try:
        verify_with_bug()
    except Exception as e:
        print(f"Error: {e}")
