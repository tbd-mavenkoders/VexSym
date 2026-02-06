"""
Example: Direct usage of VexHelix core modules without API.

This demonstrates using the core verification engine directly.
"""

import os
from vexhelix.core import (
    compile_source,
    load_projects,
    create_entangled_states,
    run_bounded_execution,
    compare_results,
)


def direct_verification_example():
    """
    Direct verification without using the API.
    """
    print("="*70)
    print("VexHelix Direct Verification Example")
    print("="*70)
    
    # Original correct implementation
    original_code = """
    int absolute_difference(int a, int b) {
        if (a > b) {
            return a - b;
        } else {
            return b - a;
        }
    }
    
    int main() {
        return absolute_difference(10, 5);
    }
    """
    
    # Decompiled version with a subtle bug
    decompiled_code = """
    int absolute_difference(int a, int b) {
        if (a >= b) {  // BUG: Should be > not >=
            return a - b;
        } else {
            return b - a;
        }
    }
    
    int main() {
        return absolute_difference(10, 5);
    }
    """
    
    print("\n1. Compiling binaries...")
    orig_bin = compile_source(original_code, is_cpp=False)
    dec_bin = compile_source(decompiled_code, is_cpp=False)
    print(f"   Original: {orig_bin}")
    print(f"   Decompiled: {dec_bin}")
    
    try:
        print("\n2. Loading binaries into angr...")
        proj_orig, proj_dec = load_projects(orig_bin, dec_bin)
        print(f"   Original arch: {proj_orig.arch}")
        print(f"   Decompiled arch: {proj_dec.arch}")
        
        print("\n3. Creating entangled symbolic states...")
        state_orig, state_dec, args = create_entangled_states(
            proj_orig,
            proj_dec,
            "absolute_difference",
            num_args=2
        )
        print(f"   Created {len(args)} shared symbolic arguments")
        
        print("\n4. Running bounded symbolic execution...")
        print("   Executing original binary...")
        states_orig = run_bounded_execution(
            proj_orig,
            state_orig,
            loop_bound=3,
            timeout_seconds=60
        )
        print(f"   Found {len(states_orig)} final states")
        
        print("   Executing decompiled binary...")
        states_dec = run_bounded_execution(
            proj_dec,
            state_dec,
            loop_bound=3,
            timeout_seconds=60
        )
        print(f"   Found {len(states_dec)} final states")
        
        print("\n5. Comparing results...")
        result = compare_results(states_orig, states_dec, args)
        
        print("\n" + "="*70)
        print("VERIFICATION RESULT")
        print("="*70)
        
        if result.equivalent:
            print("✓ Programs are EQUIVALENT within execution bounds")
            print("  No divergences detected.")
        else:
            print("✗ Programs are DIFFERENT")
            print(f"  Found {len(result.divergences)} divergence(s)")
            
            for i, div in enumerate(result.divergences, 1):
                print(f"\n  Divergence #{i}:")
                print(f"  Type: {div['type']}")
                print("  Counterexample inputs:")
                for inp in div['inputs']:
                    print(f"    {inp['name']}: {inp['value']} (0x{inp['hex'][2:]})")
                
                print(f"  Original output: {div['orig_output']['value']}")
                print(f"  Decompiled output: {div['dec_output']['value']}")
                
                if 'execution_traces' in div:
                    print("  Execution traces (last 5 BBs):")
                    orig_trace = div['execution_traces'].get('original', [])
                    dec_trace = div['execution_traces'].get('decompiled', [])
                    print(f"    Original:   {' -> '.join(orig_trace[-5:])}")
                    print(f"    Decompiled: {' -> '.join(dec_trace[-5:])}")
        
        print("\n" + "="*70)
        print("Statistics:")
        print(f"  Original states: {result.statistics['states_orig']}")
        print(f"  Decompiled states: {result.statistics['states_dec']}")
        print(f"  Comparisons attempted: {result.statistics['comparisons_attempted']}")
        print(f"  Compatible path pairs: {result.statistics['path_pairs_compatible']}")
        print("="*70)
        
    finally:
        # Cleanup
        print("\n6. Cleaning up temporary files...")
        for path in [orig_bin, dec_bin]:
            if os.path.exists(path):
                os.remove(path)
                print(f"   Removed: {path}")


def c_plus_plus_example():
    """
    Example with C++ code.
    """
    print("\n\n" + "="*70)
    print("C++ Verification Example")
    print("="*70)
    
    original_code = """
    class Calculator {
    public:
        int add(int a, int b) {
            return a + b;
        }
    };
    
    int compute(int x, int y) {
        Calculator calc;
        return calc.add(x, y);
    }
    
    int main() {
        return compute(5, 3);
    }
    """
    
    # Same as original (should be equivalent)
    decompiled_code = original_code
    
    print("\n1. Compiling C++ binaries...")
    orig_bin = compile_source(original_code, is_cpp=True)
    dec_bin = compile_source(decompiled_code, is_cpp=True)
    
    try:
        print("\n2. Loading and verifying...")
        proj_orig, proj_dec = load_projects(orig_bin, dec_bin)
        
        # Note: For C++ member functions, you'd need to handle name mangling
        # For now, we verify the standalone function
        state_orig, state_dec, args = create_entangled_states(
            proj_orig,
            proj_dec,
            "compute",
            num_args=2
        )
        
        states_orig = run_bounded_execution(proj_orig, state_orig, loop_bound=2, timeout_seconds=30)
        states_dec = run_bounded_execution(proj_dec, state_dec, loop_bound=2, timeout_seconds=30)
        
        result = compare_results(states_orig, states_dec, args)
        
        if result.equivalent:
            print("\n✓ C++ programs are equivalent!")
        else:
            print("\n✗ C++ programs differ!")
            
    finally:
        for path in [orig_bin, dec_bin]:
            if os.path.exists(path):
                os.remove(path)


if __name__ == "__main__":
    # Run examples
    direct_verification_example()
    
    # Uncomment to run C++ example
    # c_plus_plus_example()
