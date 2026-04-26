import frida
import sys
import json

APP_NAME = "native level 4"
LIB_NAME = "libnative_level_4.so"

SCRIPT = """
const LIB_NAME = %s;

function hook() {
  const mod = Process.getModuleByName(LIB_NAME);
  console.log("[+] module base: " + mod.base);

  Interceptor.attach(mod.base.add(0x205f8), {
    onEnter(args) {
      console.log("[+] HIT circuit entry");
    }
  });

  // STK[0x202] = f(STK[0x2e8], STK[0x245])
  Interceptor.attach(mod.base.add(0x55a504), {
    onEnter(args) {
      const sp = this.context.sp;
      console.log(
        "[CALL 0x202] " +
        "STK[0x2e8]=" + sp.add(0x2e8).readU8() + " " +
        "STK[0x245]=" + sp.add(0x245).readU8() + " " +
        "x0=" + (this.context.x0.toInt32() & 1) + " " +
        "x1=" + (this.context.x1.toInt32() & 1)
      );
    }
  });

  Interceptor.attach(mod.base.add(0x55a510), {
    onEnter(args) {
      const sp = this.context.sp;
      console.log(
        "[STORE 0x202] " +
        "before=" + sp.add(0x202).readU8() + " " +
        "w8=" + (this.context.x8.toInt32() & 1)
      );
    }
  });

  // STK[0x16c] = f(STK[0x202], STK[0x1d6])
  Interceptor.attach(mod.base.add(0x55bc04), {
    onEnter(args) {
      const sp = this.context.sp;
      console.log(
        "[CALL 0x16c] " +
        "STK[0x202]=" + sp.add(0x202).readU8() + " " +
        "STK[0x1d6]=" + sp.add(0x1d6).readU8() + " " +
        "x0=" + (this.context.x0.toInt32() & 1) + " " +
        "x1=" + (this.context.x1.toInt32() & 1)
      );
    }
  });

  Interceptor.attach(mod.base.add(0x55bc10), {
    onEnter(args) {
      const sp = this.context.sp;
      console.log(
        "[STORE 0x16c] " +
        "before=" + sp.add(0x16c).readU8() + " " +
        "w8=" + (this.context.x8.toInt32() & 1)
      );
    }
  });

  Interceptor.attach(mod.base.add(0x55c3dc), {
    onEnter(args) {
      console.log("[+] HIT fail_tbz");
    }
  });

  console.log("[+] chain tracer installed");
}

hook();
""" % json.dumps(LIB_NAME)

def on_message(message, data):
    print(message)

device = frida.get_usb_device(timeout=5)
session = device.attach(APP_NAME)
script = session.create_script(SCRIPT)
script.on("message", on_message)
script.load()

print("[+] Press CHECK now with the exact candidate string")
sys.stdin.read()
