import frida
import sys
import json

APP_NAME = "native level 4"
LIB_NAME = "libnative_level_4.so"

# Offsets relative to module base
OFFSETS = {
    "circuit_entry": 0x205f8,
    "fail_tbnz_block": 0x55c3cc,
    "fail_tbz_block": 0x55c3dc,
    "post_check": 0x55c3f8,
}

SCRIPT = """
const libName = %s;
const offsets = %s;

function install() {
  const mod = Process.getModuleByName(libName);
  console.log("[+] module base: " + mod.base);

  for (const [name, off] of Object.entries(offsets)) {
    Interceptor.attach(mod.base.add(off), {
      onEnter(args) {
        console.log("[HIT] " + name + " off=0x" + off.toString(16) + " x0=" + this.context.x0 + " x8=" + this.context.x8);
      }
    });
  }

  console.log("[+] block tracer installed");
}

install();
""" % (json.dumps(LIB_NAME), json.dumps(OFFSETS))

def on_message(message, data):
    print(message)

device = frida.get_usb_device(timeout=5)
session = device.attach(APP_NAME)
script = session.create_script(SCRIPT)
script.on("message", on_message)
script.load()

print("[+] Press CHECK now")
sys.stdin.read()
