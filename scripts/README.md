# Scripts

## Core successful path

- `static/01_static_extract_xor_circuit.py`  
  Extracted the large XOR-gate structure from the ARM64 native library.

- `static/02_static_solve_gf2_attempt.py`  
  Attempted to solve the statically extracted GF(2) system. Useful because it demonstrated the structure, but produced false positives due to live seed/control-flow issues.

- `core/03_live_gf2_solver_final.py`  
  Final successful solver. Uses ADB automation and Frida hooks to recover the live GF(2) input-output matrix by basis-vector probing, then solves the system.

- `tracing/04_trace_fail_source_lr.py`  
  Used LR tracing to identify which branch/control-flow path reached the return/failure block.

- `tracing/05_trace_native_return_value.py`  
  Traced the native function return path.

- `tracing/06_trace_return_inversion.py`  
  Confirmed the final `eor w8, w8, #1` inversion that required `sp+0x144 = 0`.

## Experiments

The `_research_scratch/` folder contains intermediate debugging scripts kept for transparency but not required for the final solution.
