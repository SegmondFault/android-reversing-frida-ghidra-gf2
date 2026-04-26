import frida
import sys
import json

APP_NAME = "native level 4"
LIB_NAME = "libnative_level_4.so"

CALLS = [
    (0x55bdc4, 0x15e),
    (0x55bde4, 0x15d),
    (0x55be04, 0x15c),
    (0x55be24, 0x15b),
    (0x55be44, 0x15a),
    (0x55be64, 0x159),
    (0x55be84, 0x158),
    (0x55bea4, 0x157),
    (0x55bec4, 0x156),
    (0x55bee4, 0x155),
    (0x55bf04, 0x154),
    (0x55bf24, 0x153),
    (0x55bf44, 0x152),
    (0x55bf64, 0x151),
    (0x55bf84, 0x150),
    (0x55bfa4, 0x14f),
    (0x55bfc4, 0x14e),
    (0x55bfe4, 0x14d),
    (0x55c004, 0x14c),
    (0x55c024, 0x14b),
    (0x55c044, 0x14a),
    (0x55c064, 0x149),
    (0x55c084, 0x148),
    (0x55c0a4, 0x147),
    (0x55c0c4, 0x146),
    (0x55c0e4, 0x145),
    (0x55c104, 0x144),
    (0x55c124, 0x143),
    (0x55c144, 0x142),
]

SCRIPT = """
const libName = %s;
const calls = %s;

function install() {
  const mod = Process.getModuleByName(libName);
  console.log("[+] module base: " + mod.base);

  Interceptor.attach(mod.base.add(0x205f8), {
    onEnter(args) {
      console.log("[+] HIT circuit entry");
    }
  });

  for (const [off, spoff] of calls) {
    Interceptor.attach(mod.base.add(off), {
      onEnter(args) {
        this.spoff = spoff;
        this.a = Number(this.context.x0) & 1;
        this.b = Number(this.context.x1) & 1;
      },
      onLeave(retval) {
        const r = Number(this.context.x0) & 1;
        console.log(
          "[CALL] sp+0x" + this.spoff.toString(16) +
          " a=" + this.a +
          " b=" + this.b +
          " ret=" + r +
          " xor=" + (this.a ^ this.b) +
          " xnor=" + (1 ^ this.a ^ this.b) +
          " and=" + (this.a & this.b) +
          " or=" + (this.a | this.b)
        );
      }
    });
  }

  Interceptor.attach(mod.base.add(0x55c3dc), {
    onEnter(args) {
      console.log("[+] HIT fail_tbz");
    }
  });

  console.log("[+] final call tracer installed");
}

install();
""" % (json.dumps(LIB_NAME), json.dumps(CALLS))

def on_message(message, data):
    print(message)

device = frida.get_usb_device(timeout=5)
session = device.attach(APP_NAME)
script = session.create_script(SCRIPT)
script.on("message", on_message)
script.load()

print("[+] Press CHECK now")
sys.stdin.read()
