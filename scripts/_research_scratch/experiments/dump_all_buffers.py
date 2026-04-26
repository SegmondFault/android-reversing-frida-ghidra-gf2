import frida
import sys
import os
import json
from pathlib import Path

APP_NAME = "native level 4"
LIB_NAME = "libnative_level_4.so"

OUTDIR = Path(os.environ.get("OUTDIR", "bufs_finalcheck"))
OUTDIR.mkdir(parents=True, exist_ok=True)

SCRIPT = r"""
const libName = "%s";
const hookOffset = 0x205f8;

function tryHook() {
  const mod = Process.findModuleByName(libName);
  if (mod === null) {
    console.log("[!] module not loaded yet, retrying");
    setTimeout(tryHook, 250);
    return;
  }

  console.log("[+] module base: " + mod.base);
  const addr = mod.base.add(hookOffset);
  console.log("[+] target addr: " + addr);
  console.log(hexdump(addr.sub(0x20), { length: 0x80, ansi: false }));

  Interceptor.attach(addr, {
    onEnter(args) {
      const sp = this.context.sp;
      console.log("[+] hook: " + addr);
      console.log("[+] sp: " + sp);

      // Immediate stack seed, before the circuit runs.
      const seedWindow = {};
      for (let off = 0x140; off < 0x330; off++) {
        try {
          seedWindow["0x" + off.toString(16)] = sp.add(off).readU8();
        } catch (e) {
          seedWindow["0x" + off.toString(16)] = "ERR:" + e;
        }
      }

      send({
        type: "stack_seed",
        stack_window: seedWindow
      });
      console.log("[+] sent IMMEDIATE stack_seed before circuit");

      // Dump pointed-to B buffers.
      for (let slot = 0x18; slot <= 0x138; slot += 8) {
        try {
          const ptr = sp.add(slot).readPointer();
          console.log("[+] slot 0x" + slot.toString(16) + " -> " + ptr);
          const data = ptr.readByteArray(4096);
          send({
            type: "buffer",
            slot: slot,
            ptr: ptr.toString()
          }, data);
        } catch (e) {
          console.log("[!] failed slot 0x" + slot.toString(16) + ": " + e);
        }
      }

      console.log("[+] dump done");

      // Delayed final stack, after circuit runs.
      setTimeout(function () {
        const finalWindow = {};
        for (let off = 0x140; off < 0x330; off++) {
          try {
            finalWindow["0x" + off.toString(16)] = sp.add(off).readU8();
          } catch (e) {
            finalWindow["0x" + off.toString(16)] = "ERR:" + e;
          }
        }

        send({
          type: "stack_final",
          stack_window: finalWindow
        });
        console.log("[+] sent DELAYED stack_final after circuit");
      }, 2000);
    }
  });

  console.log("[+] Hook loaded. Press CHECK in the app with a valid 64-bit input.");
  console.log("[+] Use 64 zeroes first. Ctrl+C after dump done.");
}

tryHook();
""" % LIB_NAME


def on_message(message, data):
    if message.get("type") == "send":
        payload = message.get("payload", {})

        if payload.get("type") == "stack_seed":
            with open(OUTDIR / "stack_seed.json", "w") as f:
                json.dump(payload["stack_window"], f, indent=2)
            print("[+] wrote stack_seed.json")
            return

        if payload.get("type") == "stack_final":
            with open(OUTDIR / "stack_final.json", "w") as f:
                json.dump(payload["stack_window"], f, indent=2)
            print("[+] wrote stack_final.json")
            return

        if payload.get("type") == "buffer" and data is not None:
            slot = int(payload["slot"])
            name = f"buf_B{slot:x}.bin"
            with open(OUTDIR / name, "wb") as f:
                f.write(data)
            print(f"[+] wrote {OUTDIR / name} ({len(data)} bytes) ptr={payload.get('ptr')}")
            return

        print("[send]", payload)
    else:
        print(message)


device = frida.get_usb_device(timeout=5)
session = device.attach(APP_NAME)
script = session.create_script(SCRIPT)
script.on("message", on_message)
script.load()

sys.stdin.read()
