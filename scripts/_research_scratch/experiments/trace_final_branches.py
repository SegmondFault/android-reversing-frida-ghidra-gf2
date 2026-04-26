import frida
import sys
import json

APP_NAME = "native level 4"
LIB_NAME = "libnative_level_4.so"

CHECKS = [
    # tbz checks
    {"addr": 0x55c19c, "kind": "tbz",  "spoff": 0x15e},
    {"addr": 0x55c1b0, "kind": "tbz",  "spoff": 0x15d},
    {"addr": 0x55c1c4, "kind": "tbz",  "spoff": 0x15b},
    {"addr": 0x55c1d8, "kind": "tbz",  "spoff": 0x159},
    {"addr": 0x55c1ec, "kind": "tbz",  "spoff": 0x157},
    {"addr": 0x55c200, "kind": "tbz",  "spoff": 0x155},
    {"addr": 0x55c214, "kind": "tbz",  "spoff": 0x153},
    {"addr": 0x55c228, "kind": "tbz",  "spoff": 0x152},
    {"addr": 0x55c23c, "kind": "tbz",  "spoff": 0x151},
    {"addr": 0x55c250, "kind": "tbz",  "spoff": 0x150},
    {"addr": 0x55c264, "kind": "tbz",  "spoff": 0x14f},
    {"addr": 0x55c278, "kind": "tbz",  "spoff": 0x14a},
    {"addr": 0x55c28c, "kind": "tbz",  "spoff": 0x148},
    {"addr": 0x55c2a0, "kind": "tbz",  "spoff": 0x147},
    {"addr": 0x55c2b4, "kind": "tbz",  "spoff": 0x143},
    {"addr": 0x55c2c8, "kind": "tbz",  "spoff": 0x142},

    # tbnz checks
    {"addr": 0x55c2dc, "kind": "tbnz", "spoff": 0x15c},
    {"addr": 0x55c2f0, "kind": "tbnz", "spoff": 0x15a},
    {"addr": 0x55c304, "kind": "tbnz", "spoff": 0x158},
    {"addr": 0x55c318, "kind": "tbnz", "spoff": 0x156},
    {"addr": 0x55c32c, "kind": "tbnz", "spoff": 0x154},
    {"addr": 0x55c340, "kind": "tbnz", "spoff": 0x14e},
    {"addr": 0x55c354, "kind": "tbnz", "spoff": 0x14d},
    {"addr": 0x55c368, "kind": "tbnz", "spoff": 0x14c},
    {"addr": 0x55c37c, "kind": "tbnz", "spoff": 0x14b},
    {"addr": 0x55c390, "kind": "tbnz", "spoff": 0x149},
    {"addr": 0x55c3a4, "kind": "tbnz", "spoff": 0x146},
    {"addr": 0x55c3b8, "kind": "tbnz", "spoff": 0x145},
]

SCRIPT = """
const libName = %s;
const checks = %s;

function install() {
  const mod = Process.getModuleByName(libName);
  console.log("[+] module base: " + mod.base);

  for (const c of checks) {
    Interceptor.attach(mod.base.add(c.addr), {
      onEnter(args) {
        const bit = Number(this.context.x8) & 1;
        const branchTaken =
          (c.kind === "tbz"  && bit === 0) ||
          (c.kind === "tbnz" && bit === 1);

        console.log(
          "[BR] " +
          c.kind +
          " addr=0x" + c.addr.toString(16) +
          " sp+0x" + c.spoff.toString(16) +
          " bit=" + bit +
          " branchTaken=" + branchTaken
        );
      }
    });
  }

  Interceptor.attach(mod.base.add(0x205f8), {
    onEnter(args) {
      console.log("[+] HIT circuit entry");
    }
  });

  console.log("[+] branch tracer installed");
}

install();
""" % (json.dumps(LIB_NAME), json.dumps(CHECKS))

def on_message(message, data):
    print(message)

device = frida.get_usb_device(timeout=5)
session = device.attach(APP_NAME)
script = session.create_script(SCRIPT)
script.on("message", on_message)
script.load()

print("[+] Press CHECK now")
sys.stdin.read()
