import frida
import sys
import json

APP_NAME = "native level 4"
LIB_NAME = "libnative_level_4.so"

SCRIPT = """
const libName = %s;

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

  // Final output 0x15e:
  // ldrb w9, [sp,#0x18d]
  // ldrb w8, [sp,#0x16c]
  // and w0, w9, #1
  // and w1, w8, #1
  // bl  0x5862f0
  // ldr w8, [sp,#0x138]
  // and w8, w0, w8
  // strb w8, [sp,#0x15e]
  Interceptor.attach(mod.base.add(0x55bdd0), {
    onEnter(args) {
      const sp = this.context.sp;

      const a = bit(sp.add(0x18d).readU8());
      const b = bit(sp.add(0x16c).readU8());
      const result = bit(Number(this.context.x8));

      console.log(
        "[TRUTH_15e] " +
        "a=" + a +
        " b=" + b +
        " result=" + result +
        " xor=" + (a ^ b) +
        " xnor=" + (1 ^ a ^ b) +
        " and=" + (a & b) +
        " or=" + (a | b)
      );
    }
  });

  Interceptor.attach(mod.base.add(0x55c3dc), {
    onEnter(args) {
      console.log("[+] HIT fail_tbz");
    }
  });

  console.log("[+] one-final truth tracer installed");
}

install();
""" % json.dumps(LIB_NAME)

def on_message(message, data):
    print(message)

device = frida.get_usb_device(timeout=5)
session = device.attach(APP_NAME)
script = session.create_script(SCRIPT)
script.on("message", on_message)
script.load()

print("[+] Press CHECK now")
sys.stdin.read()
