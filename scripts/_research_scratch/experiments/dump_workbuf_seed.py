import frida
import time

import os
APP_NAME = "native level 4"
OUTFILE = os.environ.get("OUTFILE", "workbuf_seed.bin")

js_code = r"""
const libName = "libnative_level_4.so";
const probeOffset = 0x20694; // first XOR region from count_xors.py
let dumped = false;

function hook() {
  let mod;
  try {
    mod = Process.getModuleByName(libName);
  } catch (e) {
    setTimeout(hook, 250);
    return;
  }

  const probe = mod.base.add(probeOffset);
  console.log("[+] probe: " + probe);

  Interceptor.attach(probe, {
    onEnter(args) {
      if (dumped) return;
      dumped = true;

      const x8 = this.context.x8;
      const len = 0x2000;

      console.log("[+] x8 workbuf: " + x8);
      console.log("[+] reading " + len + " bytes");

      const bytes = x8.readByteArray(len);
      send({ type: "workbuf", ptr: x8.toString(), len: len }, bytes);
    }
  });
}

hook();
"""

def on_message(message, data):
    if message["type"] == "send":
        payload = message.get("payload", {})
        if payload.get("type") == "workbuf":
            if data is None:
                print("[!] No data received from Frida. Pointer read failed.")
                return
            with open(OUTFILE, "wb") as f:
                f.write(data)
            print(f"[+] wrote {OUTFILE} ({len(data)} bytes)")
            print(f"[+] source ptr: {payload.get('ptr')}")
    elif message["type"] == "error":
        print("[!] JS error:")
        print(message.get("stack", message))
    else:
        print(message)

device = frida.get_usb_device(timeout=5)
session = device.attach(APP_NAME)
script = session.create_script(js_code)
script.on("message", on_message)
script.load()

print("[+] Hook loaded. Press CHECK in the app with a valid 64-bit input.")
print("[+] Ctrl+C after workbuf_seed.bin is written.")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("[+] exiting")
    session.detach()
