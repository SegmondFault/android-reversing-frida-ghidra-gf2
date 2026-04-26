import frida
import time

APP_NAME = "native level 4"

js_code = r"""
const libName = "libnative_level_4.so";
const bpbOffset = 0x200c8;
let dumped = false;

function hook() {
  let mod;

  try {
    mod = Process.getModuleByName(libName);
  } catch (e) {
    console.log("[-] lib not loaded yet, retrying...");
    setTimeout(hook, 250);
    return;
  }

  const base = mod.base;
  const bpb = base.add(bpbOffset);

  console.log("[+] lib base: " + base);
  console.log("[+] _Z1bPb: " + bpb);

  Interceptor.attach(bpb, {
    onEnter(args) {
      if (dumped) return;
      dumped = true;

      const buf = args[0];
      const len = 0x1000;

      console.log("[>] _Z1bPb buf: " + buf);
      console.log("[+] reading " + len + " bytes");

      const bytes = buf.readByteArray(len);
      send({ type: "bpb_seed", len: len, ptr: buf.toString() }, bytes);
    },

    onLeave(retval) {
      console.log("[<] _Z1bPb returned: " + retval.toInt32());
    }
  });
}

hook();
"""

def on_message(message, data):
    if message["type"] == "send":
        payload = message.get("payload", {})
        if payload.get("type") == "bpb_seed":
            with open("bpb_seed.bin", "wb") as f:
                f.write(data)
            print(f"[+] wrote bpb_seed.bin ({len(data)} bytes)")
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
print("[+] Ctrl+C after bpb_seed.bin is written.")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("[+] exiting")
    session.detach()
