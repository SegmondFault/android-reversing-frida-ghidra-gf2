import frida
import sys
import json

APP_NAME = "native level 4"
LIB_NAME = "libnative_level_4.so"

SCRIPT = """
const libName = %s;

function install() {
  const mod = Process.getModuleByName(libName);
  console.log("[+] module base: " + mod.base);

  Interceptor.attach(mod.base.add(0x205f8), {
    onEnter(args) {
      console.log("[+] HIT circuit entry");
    }
  });

  Interceptor.attach(mod.base.add(0x55c3dc), {
    onEnter(args) {
      const pc = this.context.pc;
      const lr = this.context.lr;
      const sp = this.context.sp;
      console.log("[FAIL_TBZ] pc=" + pc + " lr=" + lr + " sp=" + sp + " x0=" + this.context.x0 + " x8=" + this.context.x8);

      // Dump final stack window at the moment of failure.
      let s = "";
      for (let off = 0x142; off < 0x15f; off++) {
        try {
          s += "0x" + off.toString(16) + "=" + sp.add(off).readU8() + " ";
        } catch (e) {
          s += "0x" + off.toString(16) + "=ERR ";
        }
      }
      console.log("[STACK] " + s);
    }
  });

  console.log("[+] fail LR tracer installed");
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
