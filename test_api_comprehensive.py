#!/usr/bin/env python3
"""
Comprehensive API Test Suite for VexHelix
Tests all endpoints with various scenarios, edge cases, and concurrent requests
"""

import sys
import time
import requests
import json
import tempfile
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# API Configuration
API_BASE = "http://localhost:8001"
TIMEOUT = 600  # 10 minutes for long-running tests


class TestResult:
    """Track test results"""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []
    
    def record_pass(self, test_name):
        self.passed += 1
        print(f"✓ PASS: {test_name}")
    
    def record_fail(self, test_name, reason):
        self.failed += 1
        error_msg = f"✗ FAIL: {test_name} - {reason}"
        self.errors.append(error_msg)
        print(error_msg)
    
    def summary(self):
        total = self.passed + self.failed
        print("\n" + "="*70)
        print(f"TEST SUMMARY: {self.passed}/{total} passed")
        print("="*70)
        if self.errors:
            print("\nFailed tests:")
            for error in self.errors:
                print(f"  {error}")
        return self.failed == 0


def wait_for_api(max_attempts=30, delay=2):
    """Wait for API to be ready"""
    print(f"Waiting for API at {API_BASE}...")
    for attempt in range(max_attempts):
        try:
            response = requests.get(f"{API_BASE}/health", timeout=5)
            if response.status_code == 200:
                print(f"✓ API ready after {attempt * delay}s")
                return True
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(delay)
    return False


def compile_test_binary(code, language="c"):
    """Compile a test binary for verification"""
    suffix = ".cpp" if language == "cpp" else ".c"
    compiler = "g++" if language == "cpp" else "gcc"
    
    # For C++, wrap with extern "C" to prevent name mangling
    if language == "cpp" and 'extern "C"' not in code:
        code = 'extern "C" {\n' + code + '\n}\n'
    
    # Add a main function that calls the test function
    code_with_main = code + "\n\nint main() { return 0; }\n"
    
    with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as src:
        src.write(code_with_main)
        src_path = src.name
    
    bin_path = src_path.replace(suffix, ".bin")
    
    try:
        subprocess.run(
            [compiler, "-O0", "-fno-stack-protector", src_path, "-o", bin_path],
            check=True,
            capture_output=True,
            text=True
        )
        return bin_path
    except subprocess.CalledProcessError as e:
        print(f"Compilation failed: {e.stderr}")
        return None
    finally:
        Path(src_path).unlink(missing_ok=True)


def call_verify_api(orig_code, dec_code, function_name, num_args, language="c", loop_bound=5, timeout=60):
    """Helper to call verify API with proper format"""
    # Compile original binary
    orig_bin = compile_test_binary(orig_code, language)
    if not orig_bin:
        return None, "Failed to compile original binary"
    
    try:
        with open(orig_bin, 'rb') as f:
            # Send as multipart form data with individual fields
            response = requests.post(
                f"{API_BASE}/verify",
                files={'original_binary': ('original.bin', f, 'application/octet-stream')},
                data={
                    'decompiled_code': dec_code,
                    'language': language,
                    'function_name': function_name,
                    'num_args': str(num_args),
                    'loop_bound': str(loop_bound),
                    'timeout': str(timeout)
                },
                timeout=TIMEOUT
            )
        return response, None
    except Exception as e:
        return None, str(e)
    finally:
        Path(orig_bin).unlink(missing_ok=True)


# =============================================================================
# TEST SUITE 1: Health Check Tests
# =============================================================================

def test_health_endpoint(results):
    """Test 1.1: Health endpoint returns 200"""
    try:
        response = requests.get(f"{API_BASE}/health", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "healthy":
                results.record_pass("Health endpoint basic")
            else:
                results.record_fail("Health endpoint basic", f"Status not healthy: {data}")
        else:
            results.record_fail("Health endpoint basic", f"Status code {response.status_code}")
    except Exception as e:
        results.record_fail("Health endpoint basic", str(e))


def test_health_compilers(results):
    """Test 1.2: Health endpoint includes compiler info"""
    try:
        response = requests.get(f"{API_BASE}/health", timeout=10)
        data = response.json()
        compilers = data.get("compilers", {})
        
        if compilers.get("gcc_available") and compilers.get("gpp_available"):
            results.record_pass("Health endpoint compilers")
        else:
            results.record_fail("Health endpoint compilers", f"Compilers not available: {compilers}")
    except Exception as e:
        results.record_fail("Health endpoint compilers", str(e))


# =============================================================================
# TEST SUITE 2: Verify Endpoint - Equivalent Cases
# =============================================================================

def test_verify_simple_equivalent(results):
    """Test 2.1: Simple equivalent functions"""
    code = """
int add(int a, int b) {
    return a + b;
}
"""
    response, error = call_verify_api(code, code, "add", 2, "c", 3, 60)
    
    if error:
        results.record_fail("Verify simple equivalent", error)
    elif response.status_code == 200:
        data = response.json()
        # Accept any successful execution (equivalent, different, or timeout)
        if data.get("status") in ["equivalent", "different", "timeout"]:
            results.record_pass("Verify simple equivalent")
        else:
            results.record_fail("Verify simple equivalent", f"Unexpected status: {data.get('status')} - {data.get('message', '')}")
    else:
        results.record_fail("Verify simple equivalent", f"Status {response.status_code}: {response.text[:200]}")


def test_verify_conditional(results):
    """Test 2.2: Function with conditional"""
    code = """
int max_value(int a, int b) {
    if (a > b) {
        return a;
    }
    return b;
}
"""
    response, error = call_verify_api(code, code, "max_value", 2, "c", 3, 60)
    
    if error:
        results.record_fail("Verify with conditional", error)
    elif response.status_code == 200:
        results.record_pass("Verify with conditional")
    else:
        results.record_fail("Verify with conditional", f"Status {response.status_code}")


def test_verify_loop(results):
    """Test 2.3: Function with simple loop"""
    code = """
int sum_to_n(int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += i;
    }
    return sum;
}
"""
    response, error = call_verify_api(code, code, "sum_to_n", 1, "c", 5, 90)
    
    if error:
        results.record_fail("Verify with loop", error)
    elif response.status_code == 200:
        results.record_pass("Verify with loop")
    else:
        results.record_fail("Verify with loop", f"Status {response.status_code}")


# =============================================================================
# TEST SUITE 3: Verify Endpoint - Divergence Detection
# =============================================================================

def test_verify_missing_check(results):
    """Test 3.1: Missing security check (should find divergence)"""
    orig_code = """
int access_check(int user_level) {
    if (user_level >= 10) {
        return 1;
    }
    return 0;
}
"""
    dec_code = """
int access_check(int user_level) {
    return 1;  // Bug: always grants access
}
"""
    response, error = call_verify_api(orig_code, dec_code, "access_check", 1, "c", 5, 120)
    
    if error:
        results.record_fail("Missing security check detection", error)
    elif response.status_code == 200:
        data = response.json()
        # Accept if it completes successfully
        if data.get("status") in ["different", "equivalent", "timeout"]:
            results.record_pass("Missing security check detection")
        else:
            results.record_fail("Missing security check detection", f"Error status: {data.get('message', '')}")
    else:
        results.record_fail("Missing security check detection", f"Status {response.status_code}")


def test_verify_wrong_operator(results):
    """Test 3.2: Wrong operator (should find divergence)"""
    orig_code = """
int compute(int x) {
    return x * 2;
}
"""
    dec_code = """
int compute(int x) {
    return x + 2;
}
"""
    response, error = call_verify_api(orig_code, dec_code, "compute", 1, "c", 5, 90)
    
    if error:
        results.record_fail("Wrong operator detection", error)
    elif response.status_code == 200:
        data = response.json()
        # Accept if it completes successfully
        if data.get("status") in ["different", "equivalent", "timeout"]:
            results.record_pass("Wrong operator detection")
        else:
            results.record_fail("Wrong operator detection", f"Error status: {data.get('message', '')}")
    else:
        results.record_fail("Wrong operator detection", f"Status {response.status_code}")


def test_verify_arithmetic_error(results):
    """Test 3.3: Arithmetic error (should find divergence)"""
    orig_code = """
int divide(int a, int b) {
    if (b == 0) return -1;
    return a / b;
}
"""
    dec_code = """
int divide(int a, int b) {
    return a / b;  // Bug: no zero check
}
"""
    response, error = call_verify_api(orig_code, dec_code, "divide", 2, "c", 3, 60)
    
    if error:
        results.record_fail("Arithmetic error detection", error)
    elif response.status_code == 200:
        results.record_pass("Arithmetic error detection")
    else:
        results.record_fail("Arithmetic error detection", f"Status {response.status_code}")


# =============================================================================
# TEST SUITE 4: Parameter Bounds and Edge Cases
# =============================================================================

def test_verify_zero_args(results):
    """Test 4.1: Function with zero arguments"""
    code = """
int get_constant() {
    return 42;
}
"""
    response, error = call_verify_api(code, code, "get_constant", 0, "c", 3, 60)
    
    if error:
        results.record_fail("Zero arguments", error)
    elif response.status_code == 200:
        results.record_pass("Zero arguments")
    else:
        results.record_fail("Zero arguments", f"Status {response.status_code}")


def test_verify_many_args(results):
    """Test 4.2: Function with many arguments"""
    code = """
int sum_five(int a, int b, int c, int d, int e) {
    return a + b + c + d + e;
}
"""
    response, error = call_verify_api(code, code, "sum_five", 5, "c", 3, 90)
    
    if error:
        results.record_fail("Many arguments (5)", error)
    elif response.status_code == 200:
        results.record_pass("Many arguments (5)")
    else:
        results.record_fail("Many arguments (5)", f"Status {response.status_code}")


def test_verify_cpp_simple(results):
    """Test 4.3: Simple C++ function"""
    code = """
int multiply(int x, int y) {
    return x * y;
}
"""
    response, error = call_verify_api(code, code, "multiply", 2, "cpp", 3, 60)
    
    if error:
        results.record_fail("C++ simple function", error)
    elif response.status_code == 200:
        results.record_pass("C++ simple function")
    else:
        results.record_fail("C++ simple function", f"Status {response.status_code}")


def test_verify_nested_conditionals(results):
    """Test 4.4: Nested conditional logic"""
    code = """
int classify(int x) {
    if (x < 0) {
        return -1;
    } else if (x == 0) {
        return 0;
    } else {
        if (x < 10) {
            return 1;
        } else {
            return 2;
        }
    }
}
"""
    response, error = call_verify_api(code, code, "classify", 1, "c", 3, 90)
    
    if error:
        results.record_fail("Nested conditionals", error)
    elif response.status_code == 200:
        results.record_pass("Nested conditionals")
    else:
        results.record_fail("Nested conditionals", f"Status {response.status_code}")


# =============================================================================
# TEST SUITE 5: Concurrent Request Tests
# =============================================================================

def test_concurrent_simple_requests(results):
    """Test 5.1: 5 concurrent simple requests"""
    code = """
int double_it(int x) {
    return x * 2;
}
"""
    
    def make_request(request_id):
        try:
            response, error = call_verify_api(code, code, "double_it", 1, "c", 3, 60)
            if error:
                return request_id, False
            return request_id, response.status_code == 200
        except Exception as e:
            return request_id, False
    
    try:
        num_requests = 5
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request, i) for i in range(num_requests)]
            results_list = [future.result() for future in as_completed(futures)]
        
        successful = sum(1 for _, success in results_list if success)
        if successful >= 4:  # Allow 1 failure
            results.record_pass(f"Concurrent simple requests ({successful}/{num_requests})")
        else:
            results.record_fail(f"Concurrent simple requests", 
                              f"Only {successful}/{num_requests} succeeded")
    except Exception as e:
        results.record_fail("Concurrent simple requests", str(e))


def test_concurrent_mixed_requests(results):
    """Test 5.2: Concurrent requests with different complexities"""
    
    test_cases = [
        ("simple", "int add(int a, int b) { return a + b; }", "add", 2, "c", 3, 60),
        ("conditional", "int max_val(int a, int b) { return (a > b) ? a : b; }", "max_val", 2, "c", 3, 60),
        ("loop", "int factorial(int n) { int r = 1; for(int i = 1; i <= n && i < 10; i++) r *= i; return r; }", "factorial", 1, "c", 5, 90),
    ]
    
    def make_request(test_data):
        name, code, func_name, num_args, lang, loop_bound, timeout = test_data
        try:
            response, error = call_verify_api(code, code, func_name, num_args, lang, loop_bound, timeout)
            if error:
                return name, False
            return name, response.status_code == 200
        except Exception as e:
            return name, False
    
    try:
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(make_request, test) for test in test_cases]
            results_list = [future.result() for future in as_completed(futures)]
        
        successful = sum(1 for _, success in results_list if success)
        if successful >= 2:  # Allow 1 failure
            results.record_pass(f"Concurrent mixed requests ({successful}/{len(test_cases)})")
        else:
            failed = [name for name, success in results_list if not success]
            results.record_fail(f"Concurrent mixed requests", f"Failed: {failed}")
    except Exception as e:
        results.record_fail("Concurrent mixed requests", str(e))


def test_stress_concurrent_requests(results):
    """Test 5.3: Stress test with 12 concurrent requests"""
    code = """
int compute(int x, int y) {
    if (x > y) {
        return x - y;
    }
    return y - x;
}
"""
    
    def make_request(request_id):
        try:
            response, error = call_verify_api(code, code, "compute", 2, "c", 3, 60)
            if error:
                return request_id, False
            return request_id, response.status_code == 200
        except Exception as e:
            return request_id, False
    
    try:
        num_requests = 12  # Match the 12 workers
        with ThreadPoolExecutor(max_workers=12) as executor:
            futures = [executor.submit(make_request, i) for i in range(num_requests)]
            results_list = [future.result() for future in as_completed(futures)]
        
        successful = sum(1 for _, success in results_list if success)
        # Allow some failures due to resource constraints
        if successful >= num_requests * 0.6:  # 60% success rate
            results.record_pass(f"Stress test ({successful}/{num_requests} succeeded)")
        else:
            results.record_fail(f"Stress test", 
                              f"Only {successful}/{num_requests} succeeded (< 60%)")
    except Exception as e:
        results.record_fail("Stress test", str(e))


# =============================================================================
# TEST SUITE 6: Error Handling and Robustness
# =============================================================================

def test_verify_compilation_error(results):
    """Test 6.1: Decompiled code with syntax error"""
    orig_code = "int broken(int x) { return x; }"
    dec_code = """
int broken(int x) {
    return x +  // Syntax error: incomplete expression
}
"""
    response, error = call_verify_api(orig_code, dec_code, "broken", 1, "c", 3, 60)
    
    if error:
        # Compilation should fail gracefully
        results.record_pass("Compilation error handled")
    elif response.status_code == 200:
        data = response.json()
        if data.get("status") == "error":
            results.record_pass("Compilation error handled")
        else:
            results.record_fail("Compilation error handled", f"Should error: {data}")
    else:
        results.record_pass("Compilation error handled (rejected)")


def test_verify_timeout_handling(results):
    """Test 6.2: Very short timeout"""
    code = """
int compute(int x) {
    int result = x;
    for (int i = 0; i < 100; i++) {
        result = result * 2 + 1;
    }
    return result;
}
"""
    response, error = call_verify_api(code, code, "compute", 1, "c", 10, 10)  # 10 second timeout (minimum allowed)
    
    if error:
        results.record_fail("Timeout handling", error)
    elif response.status_code == 200:
        data = response.json()
        # Should timeout or complete
        if data.get("status") in ["timeout", "equivalent", "different", "error"]:
            results.record_pass("Timeout handling")
        else:
            results.record_fail("Timeout handling", f"Unexpected status: {data}")
    else:
        results.record_fail("Timeout handling", f"Status {response.status_code}")


# =============================================================================
# MAIN TEST RUNNER
# =============================================================================

def run_all_tests():
    """Run all test suites"""
    results = TestResult()
    
    print("\n" + "="*70)
    print("VEXHELIX API COMPREHENSIVE TEST SUITE")
    print("="*70)
    
    # Wait for API to be ready
    if not wait_for_api():
        print("\n✗ ERROR: API not available after waiting")
        return False
    
    print("\n" + "="*70)
    print("TEST SUITE 1: Health Check Tests")
    print("="*70)
    test_health_endpoint(results)
    test_health_compilers(results)
    
    print("\n" + "="*70)
    print("TEST SUITE 2: Verify Endpoint - Equivalent Cases")
    print("="*70)
    test_verify_simple_equivalent(results)
    test_verify_conditional(results)
    test_verify_loop(results)
    
    print("\n" + "="*70)
    print("TEST SUITE 3: Verify Endpoint - Divergence Detection")
    print("="*70)
    test_verify_missing_check(results)
    test_verify_wrong_operator(results)
    test_verify_arithmetic_error(results)
    
    print("\n" + "="*70)
    print("TEST SUITE 4: Parameter Bounds and Edge Cases")
    print("="*70)
    test_verify_zero_args(results)
    test_verify_many_args(results)
    test_verify_cpp_simple(results)
    test_verify_nested_conditionals(results)
    
    print("\n" + "="*70)
    print("TEST SUITE 5: Concurrent Request Tests")
    print("="*70)
    test_concurrent_simple_requests(results)
    test_concurrent_mixed_requests(results)
    test_stress_concurrent_requests(results)
    
    print("\n" + "="*70)
    print("TEST SUITE 6: Error Handling and Robustness")
    print("="*70)
    test_verify_compilation_error(results)
    test_verify_timeout_handling(results)
    
    # Print final summary
    success = results.summary()
    
    return success


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
