import frida
import sys
import json

APP_NAME = "native level 4"
LIB_NAME = "libnative_level_4.so"

# store addresses discovered earlier:
# 0x55bdd0 writes sp+0x15e, then every +0x20 roughly
STORES = [
    (0x55bdd0, 0x15e), (0x55bdf0, 0x15d), (0x55be10, 0x15c),
    (0x55be30, 0x15b), (0x55be50, 0x15a), (0x55be70, 0x159),
    (0x55be90, 0x158), (0x55beb0, 0x157), (0x55bed0, 0x156),
    (0x55bef0, 0x155), (0x55bf10, 0x154), (0x55bf30, 0x153),
    (0x55bf50, 0x152), (0x55bf70, 0x151), (0x55bf90, 0x150),
    (0x55bfb0, 0x14f), (0x55bfd0, 0x14e), (0x55bff0, 0x14d),
    (0x55c010, 0x14c), (0x55c030, 0x14b), (0x55c050, 0x14a),
    (0x55c070, 0x149), (0x55c090, 0x148), (0x55c0b0, 0x147),
    (0x55c0d0, 0x146), (0x55c0f0, 0x145), (0x55c130, 0x143),
    (0x55c150, 0x142),
]

SCRIPT = """
const libName = %s;
const stores = %s;

function install() {
  const mod = Process.getModuleByName(libName);
  console.log("[+] module base: " + mod.base);

  Interceptor.attach(mod.base.add(0x205f8), {
    onEnter(args) {
      console.log("[+] HIT circuit entry");
    }
  });

  for (const [off, spoff] of stores) {
    Interceptor.attach(mod.base.add(off), {
      onEnter(args) {
        const sp = this.context.sp;
        const before = sp.add(spoff).readU8();
        const w8 = Number(this.context.x8) & 0xff;
        const w9 = Number(this.context.x9) & 0xff;
        console.log(
          "[STORE] addr=0x" + off.toString(16) +
          " sp+0x" + spoff.toString(16) +
          " before=" + before +
          " x8low=" + w8 +
          " x9low=" + w9
        );
      },
      onLeave(retval) {
        // after write
      }
    });
  }

  Interceptor.attach(mod.base.add(0x55c3dc), {
    onEnter(args) {
      console.log("[+] HIT fail_tbz");
    }
  });

  console.log("[+] stack write tracer installed");
}

install();
""" % (json.dumps(LIB_NAME), json.dumps(STORES))

def on_message(message, data):
    print(message)

device = frida.get_usb_device(timeout=5)
session = device.attach(APP_NAME)
script = session.create_script(SCRIPT)
script.on("message", on_message)
script.load()

print("[+] Press CHECK now")
sys.stdin.read()
