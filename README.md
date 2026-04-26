## Problem

The challenge was a native Android password checker. The visible app accepted a 64-bit binary string, but the actual check was implemented in an ARM64 native library rather than directly in Java/Kotlin.

The goal was to recover a valid password and understand the checking logic well enough to explain the method.

## Tools Used

- Ghidra: static inspection of the native ARM64 library
- Capstone: scripted disassembly and instruction inspection
- pyelftools: ELF parsing and section/address handling
- Frida: live instrumentation of the running Android app
- ADB: app launch, input automation, and interaction with the emulator/device
- Python: orchestration, probing, matrix construction, and GF(2) solving

## Method

1. Extracted the APK and identified the ARM64 native library.
2. Used Ghidra and scripted disassembly to locate the password-checking region.
3. Found that the check behaved like a large XOR-based Boolean circuit.
4. Built an initial static model of the circuit.
5. Attempted to solve the extracted system over GF(2).
6. Hit a roadblock: the static solution produced false positives because it missed live seed-state and control-flow details.
7. Switched to treating the running app as an oracle.
8. Used Frida hooks to inspect the native check during execution.
9. Used ADB automation to enter candidate inputs and trigger the check.
10. Probed the checker with the zero vector and each 64-bit basis vector.
11. Reconstructed the live input-output matrix over GF(2).
12. Solved the resulting linear system using custom Gaussian elimination.
13. Verified the recovered password inside the Android app.

## Why GF(2)?

The native check was dominated by XOR-style Boolean logic. XOR maps naturally onto arithmetic over GF(2), where:

- `0 + 0 = 0`
- `1 + 0 = 1`
- `0 + 1 = 1`
- `1 + 1 = 0`

This allowed the password check to be modelled as a linear system over bits rather than as an opaque block of native code.

## Roadblock

The first static extraction was useful but incomplete. It recovered the broad XOR structure, but it did not fully reproduce the runtime state of the app.

That produced plausible-looking candidates that failed in the live application.

The solution was to stop relying only on the static model and instead recover the actual runtime transformation by probing the live checker.

## Key Lesson

Static analysis gave the map, but live instrumentation showed where the map was wrong.

The successful approach combined both: static reverse engineering to understand the structure, and dynamic Frida/ADB probing to recover the exact runtime behaviour.

## Ethics and Scope

This repository documents a controlled educational Android reversing challenge. It does not target third-party applications, services, or real user data.
