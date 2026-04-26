import frida
import sys
import json

APP_NAME = "native level 4"
LIB_NAME = "libnative_level_4.so"

# store_addr, output_spoff, input_a_spoff, input_b_spoff
CHECKS = [
    (0x55bdd0, 0x15e, 0x18d, 0x16c),
    (0x55bdf0, 0x15d, 0x177, 0x184),
    (0x55be10, 0x15c, 0x175, 0x194),
    (0x55be30, 0x15b, 0x165, 0x171),
    (0x55be50, 0x15a, 0x174, 0x170),
    (0x55be70, 0x159, 0x19f, 0x186),
    (0x55be90, 0x158, 0x176, 0x17e),
    (0x55beb0, 0x157, 0x167, 0x162),
    (0x55bed0, 0x156, 0x191, 0x193),
    (0x55bef0, 0x155, 0x16d, 0x19a),
    (0x55bf10, 0x154, 0x19e, 0x19c),
    (0x55bf30, 0x153, 0x19d, 0x195),
    (0x55bf50, 0x152, 0x182, 0x178),
    (0x55bf70, 0x151, 0x17c, 0x168),
    (0x55bf90, 0x150, 0x185, 0x197),
    (0x55bfb0, 0x14f, 0x189, 0x190),
    (0x55bfd0, 0x14e, 0x187, 0x173),
    (0x55bff0, 0x14d, 0x180, 0x17b),
    (0x55c010, 0x14c, 0x192, 0x199),
    (0x55c030, 0x14b, 0x196, 0x183),
    (0x55c050, 0x14a, 0x16b, 0x1a0),
    (0x55c070, 0x149, 0x16a, 0x166),
    (0x55c090, 0x148, 0x179, 0x18e),
    (0x55c0b0, 0x147, 0x17f, 0x164),
    (0x55c0d0, 0x146, 0x18b, 0x16f),
    (0x55c0f0, 0x145, 0x181, 0x18c),
    (0x55c110, 0x144, 0x163, 0x172),
    (0x55c130, 0x143, 0x198, 0x19b),
    (0x55c150, 0x142, 0x198, 0x19b),  # suspicious duplicate, but good enough to inspect
]

SCRIPT = """
const libName = %s;
const checks = %s;

function bit(x) {
  return x & 1;
}

function install() {
  const mod = Process.getModuleByName(libName);
  console.log("[+] module base: " + mod.base);

  Interceptor.attach(mod.base.add(0x205f8), {
    onEnter(args) {
      console.log("[+] HIT circuit entry");
    }
  });

  for (const [addr, outOff, aOff, bOff] of checks) {
    Interceptor.attach(mod.base.add(addr), {
      onEnter(args) {
        const sp = this.context.sp;

        const a = bit(sp.add(aOff).readU8());
        const b = bit(sp.add(bOff).readU8());
        const r = bit(Number(this.context.x8));

        console.log(
          "[TRUTH] out=0x" + outOff.toString(16) +
          " a@0x" + aOff.toString(16) + "=" + a +
          " b@0x" + bOff.toString(16) + "=" + b +
          " result=" + r +
          " xor=" + (a ^ b) +
          " xnor=" + (1 ^ a ^ b) +
          " and=" + (a & b) +
          " or=" + (a | b)
        );
      }
    });
  }

  Interceptor.attach(mod.base.add(0x55c3dc), {
    onEnter(args) {
      console.log("[+] HIT fail_tbz");
    }
  });

  console.log("[+] final truth tracer installed");
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
