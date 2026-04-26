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

function hook() {
  const mod = Process.findModuleByName(libName);
  if (mod === null) {
    console.log("[!] module not loaded yet, retrying");
    setTimeout(hook, 250);
    return;
  }

  console.log("[+] module base: " + mod.base);
  const addr = mod.base.add(hookOffset);
  console.log("[+] hook addr: " + addr);

  Interceptor.attach(addr, {
    onEnter(args) {
      const sp = this.context.sp;
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

      console.log("[+] sent stack_seed only");
    }
  });

  console.log("[+] stack seed hook installed. Press CHECK with 64 zeroes.");
}

hook();
""" % LIB_NAME

def on_message(message, data):
    if message.get("type") == "send":
        payload = message.get("payload", {})
        if payload.get("type") == "stack_seed":
            with open(OUTDIR / "stack_seed.json", "w") as f:
                json.dump(payload["stack_window"], f, indent=2)
            print("[+] wrote stack_seed.json")
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
