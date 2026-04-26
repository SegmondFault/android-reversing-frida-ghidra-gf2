# Android Reversing with Frida, Ghidra, and GF(2)

This project documents the solution of a native Android password-checking challenge using static reverse engineering, dynamic instrumentation, automated live probing, and GF(2) linear algebra.

The target implemented a large XOR-based Boolean circuit inside an ARM64 native library. Initial static analysis with Ghidra and scripted disassembly revealed the broad structure of the check, but the first static GF(2) solver produced false positives due to live seed-state and control-flow details.

The final solution used Frida hooks and ADB automation to recover the real input-output behaviour of the running app. By probing the checker with the zero vector and each 64-bit basis vector, the password check was reconstructed as a live GF(2) linear system and solved with a custom Python Gaussian elimination routine.

## Result

A valid 64-bit password was recovered and verified in the Android app:

```text
0010111010001101111010000001000010000000000000000000000000000000
```

