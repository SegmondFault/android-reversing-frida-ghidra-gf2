import frida
import sys
import json

APP_NAME = "native level 4"
LIB_NAME = "libnative_level_4.so"

SCRIPT = """
const libName = %s;

function install() {
  const mod = Process.getModuleByName(libName);
  console.log("[+] module base:", mod.base);

  // Gate: STK[0x16c] = f(STK[0x202], STK[0x1d6])
  // call_addr 0x65c004, store_addr 0x65c010
  Interceptor.attach(mod.base.add(0x55c004), {
    onEnter(args) {
      const sp = this.context.sp;
      const a = sp.add(0x202).readU8() & 1;
      const b = sp.add(0x1d6).readU8() & 1;
      console.log("[CALL_16c] before call a=STK[0x202]=" + a + " b=STK[0x1d6]=" + b);
    },
    onLeave(retval) {
      console.log("[CALL_16c] retval=" + retval + " low=" + (retval.toInt32() & 1));
    }
  });

  Interceptor.attach(mod.base.add(0x55c010), {
    onEnter(args) {
      const sp = this.context.sp;
      const before = sp.add(0x16c).readU8() & 1;
      const w0 = this.context.x0.toInt32() & 1;
      const w8 = this.context.x8.toInt32() & 1;
      console.log("[STORE_16c] before=" + before + " w0low=" + w0 + " w8low=" + w8);
    },
    onLeave(retval) {
      const sp = this.context.sp;
      const after = sp.add(0x16c).readU8() & 1;
      console.log("[STORE_16c] after=" + after);
    }
  });

  Interceptor.attach(mod.base.add(0x55c3dc), {
    onEnter(args) {
      console.log("[+] HIT fail_tbz");
    }
  });

  console.log("[+] 0x16c gate tracer installed");
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
