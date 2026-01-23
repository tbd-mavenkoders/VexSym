# VexHelix

**Bounded Relational Symbolic Execution for Decompilation Verification**

VexHelix verifies semantic equivalence between original binaries and decompiled source code using VEX IR and angr.

## Quick Start

### Docker (Recommended)
```bash
# Build and run
docker build -t vexhelix .
docker run -d -p 8000:8000 vexhelix

# Test API
curl http://localhost:8000/health
```

### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Start API server (12 workers for high parallelism)
uvicorn vexhelix.api.server:app --host 0.0.0.0 --port 8000 --workers 12

# Or use background mode
uvicorn vexhelix.api.server:app --host 0.0.0.0 --port 8000 --workers 12 &
```

## API Usage

### Health Check
```bash
curl http://localhost:8000/health
```

### Verify Decompilation
```bash
curl -X POST http://localhost:8000/verify \
  -H "Content-Type: application/json" \
  -d '{
    "decompiled_code": "int access_check(int user_level) { return 1; }",
    "language": "c",
    "function_name": "access_check",
    "num_args": 1,
    "loop_bound": 5,
    "timeout": 300
  }'
```

### Example Response
```json
{
  "status": "different",
  "equivalent": false,
  "divergences": [{
    "type": "return_value_mismatch",
    "inputs": [{"name": "arg0", "value": 9}],
    "orig_output": {"value": 0},
    "dec_output": {"value": 1}
  }]
}
```

## Python Usage

```python
from vexhelix import (
    compile_source,
    load_projects, 
    create_entangled_states,
    run_bounded_execution,
    compare_results
)

# Compile decompiled code
binary_path = compile_source("int main() { return 42; }", "c", "main", 0)

# Load both binaries
orig_proj, dec_proj = load_projects("original.bin", binary_path)

# Create entangled states
orig_state, dec_state = create_entangled_states(
    orig_proj, dec_proj, "main", 0
)

# Execute symbolically
orig_results = run_bounded_execution(
    orig_state, orig_proj, loop_bound=5, timeout=300
)
dec_results = run_bounded_execution(
    dec_state, dec_proj, loop_bound=5, timeout=300
)

# Compare
result = compare_results(orig_results, dec_results, timeout=300)
print(f"Equivalent: {result.equivalent}")
if not result.equivalent:
    for div in result.divergences:
        print(f"Counterexample: {div['inputs']}")
```

## Project Structure

```
vexhelix/
├── vexhelix/
│   ├── core/
│   │   ├── compiler.py      # GCC/G++ compilation
│   │   ├── loader.py        # Binary loading with angr
│   │   ├── entangler.py     # Shared symbolic states
│   │   ├── executor.py      # Bounded execution
│   │   └── comparator.py    # SMT-based comparison
│   └── api/
│       ├── server.py        # FastAPI REST API
│       └── models.py        # Pydantic models
├── Dockerfile               # Container definition (12 workers)
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Key Features

- **VEX IR Only**: Uses VEX for both binaries (no LLVM/IR mismatch)
- **Observable Divergence**: Detects output differences, not CFG matching
- **Shared Symbolic Variables**: Ensures identical inputs for fair comparison
- **C/C++ Support**: Handles vtables and object-oriented code
- **Bounded Execution**: LoopSeer prevents infinite loops
- **Concrete Counterexamples**: Returns specific inputs that trigger bugs
- **High Parallelism**: 12 concurrent workers for fast verification

## License

MIT License. See [LICENSE](LICENSE) for details.
            'decompiled_code': decompiled_code,
            'language': 'c',
            'function_name': 'compute',
            'num_args': 1,
            'loop_bound': 5,
            'timeout': 300
        }
    )

result = response.json()
print(f"Status: {result['status']}")
print(f"Equivalent: {result.get('equivalent')}")

if result['status'] == 'different':
    for div in result['divergences']:
        print(f"\nCounterexample: {div['inputs']}")
        print(f"Original output: {div['orig_output']}")
        print(f"Decompiled output: {div['dec_output']}")
```

### Using Core Library Directly

```python
from vexhelix.core import (
    compile_source,
    load_projects,
    create_entangled_states,
    run_bounded_execution,
    compare_results,
)

# Compile decompiled source
dec_bin = compile_source(decompiled_code, is_cpp=False)

# Load both binaries
proj_orig, proj_dec = load_projects("original.bin", dec_bin)

# Create entangled states
state_o, state_d, args = create_entangled_states(
    proj_orig, proj_dec, "compute", num_args=1
)

# Run symbolic execution
states_o = run_bounded_execution(proj_orig, state_o, loop_bound=5)
states_d = run_bounded_execution(proj_dec, state_d, loop_bound=5)

# Compare results
result = compare_results(states_o, states_d, args)

if result.equivalent:
    print("✓ Programs are equivalent")
else:
    print("✗ Found divergences:")
    for div in result.divergences:
        print(f"  Input: {div['inputs']}")
```

## API Reference

### POST /verify

Verify semantic equivalence between original binary and decompiled code.

**Request:**
- `original_binary` (file): Original binary executable
- `decompiled_code` (string): Decompiled C/C++ source code
- `language` (string): "c" or "cpp"
- `function_name` (string): Name of function to verify (default: "main")
- `num_args` (int): Number of arguments (default: 3)
- `loop_bound` (int): Maximum loop iterations (default: 5)
- `timeout` (int): Execution timeout in seconds (default: 300)

**Response:**
```json
{
  "status": "equivalent|different|error|timeout",
  "equivalent": true,
  "divergences": [],
  "statistics": {
    "states_orig": 2,
    "states_dec": 2,
    "comparisons_attempted": 4,
    "path_pairs_compatible": 4
  }
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "compilers": {
    "gcc_available": true,
    "gcc_version": "gcc (Ubuntu 13.3.0) 13.3.0",
    "gpp_available": true,
    "gpp_version": "g++ (Ubuntu 13.3.0) 13.3.0"
  }
}
```

### POST /analyze-binary

Analyze a binary and return metadata.

**Request:**
- `binary` (file): Binary file to analyze

**Response:**
```json
{
  "filename": "example.bin",
  "architecture": "AMD64",
  "bits": 64,
  "entry_point": "0x401000",
  "functions": [
    {"name": "main", "address": "0x401150", "size": 42},
    {"name": "compute", "address": "0x401180", "size": 28}
  ]
}
```

## Architecture

### Core Modules

- **compiler.py**: Compiles decompiled C/C++ code with specific flags (-O0, -fno-stack-protector)
- **loader.py**: Loads binaries into angr projects using CLE
- **entangler.py**: Creates synchronized symbolic states with shared variables
- **executor.py**: Runs bounded symbolic execution using LoopSeer
- **comparator.py**: Performs Cartesian product comparison and generates counterexamples

### Why VEX IR?

VexHelix uses VEX IR instead of LLVM IR because:

1. **Native Binary Support**: VEX lifts machine code directly without lossy transformations
2. **No Lifting Artifacts**: Avoids bugs in binary-to-LLVM tools like McSema
3. **Symmetric Analysis**: Both binaries use the same IR, eliminating IR mismatch issues
4. **Memory Model**: VEX handles raw memory operations better than LLVM's typed model

## Testing

```bash
# Run all tests
pytest vexhelix/tests/ -v

# Run specific test
pytest vexhelix/tests/test_integration.py -v

# Run with coverage
pytest --cov=vexhelix vexhelix/tests/
```

## Examples

### Example 1: Detecting Missing Instructions

```python
# Original has security check
original = """
int check_access(int admin) {
    if (admin == 1) {
        return 100;  // Grant access
    }
    return 0;  // Deny access
}
"""

# Decompiler removed the check (SECURITY BUG!)
decompiled = """
int check_access(int admin) {
    return 100;  // Always grant access
}
"""

# VexHelix will find: For admin=0, original returns 0, decompiled returns 100
```

### Example 2: Detecting Off-by-One Errors

```python
# Original
original = """
int count_up_to(int limit) {
    int sum = 0;
    for (int i = 0; i < limit; i++) {
        sum += i;
    }
    return sum;
}
"""

# Decompiler made off-by-one error
decompiled = """
int count_up_to(int limit) {
    int sum = 0;
    for (int i = 0; i <= limit; i++) {  // BUG: <= instead of <
        sum += i;
    }
    return sum;
}
"""

# VexHelix will find concrete limit value where outputs differ
```

## Performance Tuning

### Loop Bounds

Higher loop bounds increase coverage but slow execution:
- `loop_bound=3`: Fast, good for simple functions
- `loop_bound=5`: Balanced (default)
- `loop_bound=10`: Thorough but slow

### Timeouts

Set appropriate timeouts based on function complexity:
- Simple functions: 60 seconds
- Medium complexity: 300 seconds (default)
- Complex functions: 600-3600 seconds

### Memory Comparison

Enable memory comparison for functions that modify memory:
```python
compare_memory=True,
memory_regions=[(buffer_addr, buffer_size)]
```

## Limitations

1. **Halting Problem**: Cannot verify infinite loops (bounded to `loop_bound`)
2. **External Functions**: System calls and library functions are not fully modeled
3. **Floating Point**: Limited support for floating-point arithmetic
4. **Symbolic Explosion**: Very complex functions may timeout

## Comparison with D-Helix

| Feature | D-Helix | VexHelix |
|---------|---------|----------|
| Approach | CFG Isomorphism | Observable Divergence |
| IR | KLEE (LLVM) + Angr (VEX) | VEX only |
| Handles Missing Instructions | ❌ Crashes | ✅ Detects divergence |
| Handles Partial Decompilation | ❌ Fails | ✅ Works |
| Robustness | Low (IndexError) | High |
| False Positives | Medium | Low |

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Citation

If you use VexHelix in academic research, please cite:

```bibtex
@software{vexhelix2026,
  title={VexHelix: Bounded Relational Symbolic Execution for Decompilation Verification},
  author={VexHelix Project},
  year={2026},
  url={https://github.com/yourusername/vexhelix}
}
```

## License

MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- **angr**: Binary analysis framework
- **Z3**: SMT solver
- **Research**: Based on principles from bounded model checking and relational verification

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/yourusername/vexhelix/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/vexhelix/discussions)

## Roadmap

- [ ] LLVM IR support (optional alternative to VEX)
- [ ] Enhanced C++ vtable analysis
- [ ] Parallel execution for faster verification
- [ ] GUI for visualization
- [ ] Integration with popular decompilers (Ghidra, IDA Pro)

---

**Made with ❤️ for the binary analysis community**
