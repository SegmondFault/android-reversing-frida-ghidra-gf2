import frida
import subprocess
import time
import json
import os
from pathlib import Path

APP_NAME = "native level 4"
PKG = "com.example.native_simple"
LIB_NAME = "libnative_level_4.so"

# Override if needed:
# TAP_X=340 TAP_Y=190 ./angrvenv/bin/python live_solve_level4.py
TAP_X = int(os.environ.get("TAP_X", "340"))
TAP_Y = int(os.environ.get("TAP_Y", "190"))

OUTS = [
    0x15e, 0x15d, 0x15b, 0x159,
    0x157, 0x155, 0x153, 0x152,
    0x151, 0x150, 0x14f, 0x14a,
    0x148, 0x147, 0x143, 0x142,

    0x15c, 0x15a, 0x158, 0x156,
    0x154, 0x14e, 0x14d, 0x14c,
    0x14b, 0x149, 0x146, 0x145,
]

TARGET = [
    1, 1, 1, 1,
    1, 1, 1, 1,
    1, 1, 1, 1,
    1, 1, 1, 1,

    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
]

SCRIPT = r"""
const libName = "%s";
const hookOffset = 0x55c3dc;

function install() {
  const mod = Process.findModuleByName(libName);
  if (mod === null) {
    setTimeout(install, 100);
    return;
  }

  const addr = mod.base.add(hookOffset);

  Interceptor.attach(addr, {
    onEnter(args) {
      const sp = this.context.sp;

      const out = {};
        const offs = %s;

        for (let i = 0; i < offs.length; i++) {
          const off = offs[i];
          try {
            out["0x" + off.toString(16)] = sp.add(off).readU8() & 1;
          } catch (e) {
            out["0x" + off.toString(16)] = "ERR";
          }
        }

        send({ type: "final", values: out });
    }
  });

  send({ type: "ready" });
}

install();
""" % (LIB_NAME, json.dumps(OUTS))


def adb(*args):
    return subprocess.run(["adb", *args], check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def launch_app():
    adb("shell", "am", "force-stop", PKG)
    adb("shell", "pm", "clear", PKG)
    time.sleep(0.4)
    adb("shell", "monkey", "-p", PKG, "-c", "android.intent.category.LAUNCHER", "1")
    time.sleep(1.2)

def enter_and_check(bits):
    # Fresh app state: field is empty.
    adb("shell", "input", "tap", "540", "310")
    time.sleep(0.3)
    adb("shell", "input", "text", bits)
    time.sleep(0.4)
    adb("shell", "input", "tap", str(TAP_X), str(TAP_Y))

def capture(bits):
    result = {"ready": False, "values": None}

    launch_app()

    device = frida.get_usb_device(timeout=5)
    session = device.attach(APP_NAME)
    script = session.create_script(SCRIPT)

    def on_message(message, data):
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "ready":
                result["ready"] = True
            elif payload.get("type") == "final":
                result["values"] = payload["values"]
        else:
            print("[frida]", message)

    script.on("message", on_message)
    script.load()

    timeout = time.time() + 10
    while not result["ready"] and time.time() < timeout:
        time.sleep(0.05)

    print("[+] entering bits and tapping CHECK")
    enter_and_check(bits)
    print("[+] waiting for final values")

    timeout = time.time() + 10
    while result["values"] is None and time.time() < timeout:
        time.sleep(0.05)

    session.detach()

    if result["values"] is None:
        raise RuntimeError("No final values captured. Either CHECK was not tapped, hook offset did not hit, or delay too short.")

    vec = []
    for off in OUTS:
        v = result["values"][hex(off)]
        if v not in (0, 1):
            raise RuntimeError(f"Bad read at {hex(off)}: {v}")
        vec.append(v)

    return vec


def gf2_solve(rows, rhs, nvars):
    # rows are integer bitmasks, rhs bits
    rows = rows[:]
    rhs = rhs[:]
    pivots = {}
    r = 0

    for c in range(nvars):
        pivot = None
        for i in range(r, len(rows)):
            if (rows[i] >> c) & 1:
                pivot = i
                break

        if pivot is None:
            continue

        rows[r], rows[pivot] = rows[pivot], rows[r]
        rhs[r], rhs[pivot] = rhs[pivot], rhs[r]

        for i in range(len(rows)):
            if i != r and ((rows[i] >> c) & 1):
                rows[i] ^= rows[r]
                rhs[i] ^= rhs[r]

        pivots[c] = r
        r += 1

    for i in range(r, len(rows)):
        if rows[i] == 0 and rhs[i]:
            raise RuntimeError("No solution")

    x = 0
    for c, row_i in pivots.items():
        if rhs[row_i]:
            x |= (1 << c)

    return x


def main():
    print(f"[+] using CHECK tap: {TAP_X},{TAP_Y}")
    print("[+] capturing zero vector")
    zero = capture("0" * 64)
    print("[+] zero:", "".join(map(str, zero)))

    cols = []
    for i in range(64):
        bits = ["0"] * 64
        bits[i] = "1"
        s = "".join(bits)

        print(f"[+] probing bit {i:02d}: {s}")
        v = capture(s)
        col = [a ^ b for a, b in zip(v, zero)]
        cols.append(col)

    # Build 28 equations as row masks across 64 vars.
    rows = []
    rhs = []
    for out_i in range(len(OUTS)):
        mask = 0
        for bit_i in range(64):
            if cols[bit_i][out_i]:
                mask |= (1 << bit_i)

        rows.append(mask)
        rhs.append(TARGET[out_i] ^ zero[out_i])

    sol = gf2_solve(rows, rhs, 64)
    password = "".join("1" if ((sol >> i) & 1) else "0" for i in range(64))

    print("\n[+] LIVE candidate:")
    print(password)
    print("[+] grouped:")
    print(" ".join(password[i:i+8] for i in range(0, 64, 8)))

    print("[+] verifying live candidate")
    live = capture(password)
    bad = []
    for off, want, got in zip(OUTS, TARGET, live):
        if want != got:
            bad.append((off, want, got))

    print("[+] failures:", len(bad))
    for off, want, got in bad:
        print(f"0x{off:x}: want {want}, got {got}")


if __name__ == "__main__":
    main()
