# VexHelix

**Bounded Relational Symbolic Execution for Decompilation Verification**

VexHelix automatically verifies whether decompiled source code is
semantically equivalent to its original binary.  It compiles the
decompiled C/C++ source, lifts both executables to VEX IR via
[angr](https://angr.io), executes them symbolically with shared
symbolic inputs, and uses an SMT solver to find concrete
counter-examples that trigger divergent behaviour.

---

## Key Ideas

| Concept | Detail |
|---|---|
| **IR choice** | VEX IR for *both* binaries — no lossy binary→LLVM lifting. |
| **Relational execution** | Shared symbolic variables ensure fair input comparison. |
| **Observable divergence** | Compares return values (and optionally memory), not CFG structure. |
| **Bounded loops** | `LoopSeer` caps iteration count, side-stepping the halting problem. |
| **Concrete counter-examples** | When a difference is found the solver returns specific inputs. |

## Quick Start

### Docker (recommended)

```bash
docker build -t vexhelix .
docker run -d -p 8000:8000 vexhelix
curl http://localhost:8000/health
```

### Local install

```bash
pip install -e ".[dev]"          # editable install with test deps
# or
pip install -r requirements.txt  # exact pinned versions

# start server
uvicorn vexhelix.api.server:app --host 0.0.0.0 --port 8000
```

### Verify a decompilation

```bash
# compile a small original binary
echo 'int access_check(int l){if(l>=10)return 1;return 0;} int main(){return 0;}' \
  | gcc -x c -O0 -fno-stack-protector -no-pie -o /tmp/orig.bin -

# send to VexHelix (decompiled code has a bug)
curl -X POST http://localhost:8000/verify \
  -F original_binary=@/tmp/orig.bin \
  -F 'decompiled_code=int access_check(int l){return 1;}' \
  -F language=c \
  -F function_name=access_check \
  -F num_args=1 \
  -F loop_bound=5 \
  -F timeout=120
```

The response will report `"status": "different"` and include a concrete
input (e.g. `l = 0`) that triggers the divergence.

---

## Project Layout

```
vexhelix/
├── core/
│   ├── compiler.py      # GCC/G++ harness (-O0, -fno-stack-protector)
│   ├── loader.py         # angr/CLE binary loading
│   ├── entangler.py      # shared symbolic state creation
│   ├── executor.py       # LoopSeer-bounded symbolic execution
│   └── comparator.py     # Cartesian-product SMT comparison
├── api/
│   ├── server.py         # FastAPI REST endpoints
│   └── models.py         # Pydantic request / response schemas
├── examples/
│   ├── simple_verification.py
│   └── direct_usage.py
└── tests/
    ├── test_compiler.py
    └── test_integration.py
```

## API Reference

### `GET /health`

Returns server status and compiler availability.

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

### `POST /verify`  (multipart/form-data)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `original_binary` | file | *required* | Original ELF binary |
| `decompiled_code` | string | *required* | Decompiled C/C++ source |
| `language` | `c` \| `cpp` | `c` | Source language |
| `function_name` | string | `main` | Function to verify |
| `num_args` | int (0–10) | `3` | Number of arguments |
| `loop_bound` | int (1–20) | `5` | Max loop iterations |
| `timeout` | int (10–3600) | `300` | Timeout in seconds |

**Response** (abbreviated):

```json
{
  "status": "different",
  "equivalent": false,
  "divergences": [
    {
      "type": "return_value_mismatch",
      "inputs": [{"name": "arg0", "value": 0, "hex": "0x0"}],
      "orig_output": {"value": 0, "hex": "0x0"},
      "dec_output":  {"value": 1, "hex": "0x1"}
    }
  ],
  "statistics": {
    "states_orig": 2,
    "states_dec": 1,
    "comparisons_attempted": 2,
    "path_pairs_compatible": 2
  }
}
```

### `POST /analyze-binary`

Upload a binary to inspect its metadata (architecture, entry point,
symbol list).

## Python Library Usage

```python
from vexhelix import (
    compile_source,
    load_projects,
    create_entangled_states,
    run_bounded_execution,
    compare_results,
)

dec_bin = compile_source(decompiled_code, is_cpp=False)
proj_o, proj_d = load_projects("original.bin", dec_bin)
st_o, st_d, args = create_entangled_states(proj_o, proj_d, "compute", num_args=1)

states_o = run_bounded_execution(proj_o, st_o, loop_bound=5)
states_d = run_bounded_execution(proj_d, st_d, loop_bound=5)

result = compare_results(states_o, states_d, args)
if result.equivalent:
    print("Programs are equivalent within bounds")
else:
    for d in result.divergences:
        print(d["inputs"], d["orig_output"], d["dec_output"])
```

## Running Tests

```bash
pytest                        # runs all tests
pytest -k test_compiler       # compiler tests only
pytest --cov=vexhelix         # with coverage
```

## Docker

The provided `Dockerfile` builds on Ubuntu 24.04 with Python 3.12 and
GCC/G++ 13.  It starts Uvicorn with 12 workers by default.

```bash
docker build -t vexhelix .
docker run -d -p 8000:8000 --name vexhelix vexhelix
docker logs -f vexhelix
```

## Comparison with D-Helix

| | D-Helix | VexHelix |
|---|---|---|
| Approach | CFG isomorphism | Observable divergence |
| IR | KLEE (LLVM) + angr (VEX) | VEX only |
| Missing instructions | Crashes (`IndexError`) | Detects divergence |
| Partial decompilation | Fails | Works |

## Limitations

* **Bounded verification** — loops are capped at `loop_bound` iterations.
* **External functions** — libc / syscalls are not fully modelled
  (`auto_load_libs=False`).
* **Floating-point** — limited solver support for FP arithmetic.
* **Path explosion** — highly complex functions may time out.

## Citation

```bibtex
@software{vexhelix2026,
  title   = {VexHelix: Bounded Relational Symbolic Execution
             for Decompilation Verification},
  author  = {{VexHelix Authors}},
  year    = {2026},
  url     = {https://github.com/tbd-mavenkoders/VexHelix}
}
```

## License

MIT — see [LICENSE](LICENSE).
