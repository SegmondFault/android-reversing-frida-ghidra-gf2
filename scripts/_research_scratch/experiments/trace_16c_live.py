import frida
import sys
import json

APP_NAME = "native level 4"
LIB_NAME = "libnative_level_4.so"

SCRIPT = """
const libName = %s;

function waitForModule(name) {
  const m = Process.findModuleByName(name);
  if (m) return m;
  setTimeout(function () { install(); }, 250);
  return null;
}

function u8(sp, off) {
  return sp.add(off).readU8() & 1;
}

function install() {
  const mod = waitForModule(libName);
  if (!mod) return;

  console.log("[+] module base: " + mod.base);

  Interceptor.attach(mod.base.add(0x205f8), {
    onEnter(args) {
      console.log("[+] HIT circuit entry");
    }
  });

  Interceptor.attach(mod.base.add(0x55a944), {
    onEnter(args) {
      const sp = this.context.sp;
      console.log(
        "[CALL producer 0x202] " +
        "STK[0x2e8]=" + u8(sp, 0x2e8) + " " +
        "STK[0x245]=" + u8(sp, 0x245) + " " +
        "x0=" + (this.context.x0.toInt32() & 1) + " " +
        "x1=" + (this.context.x1.toInt32() & 1)
      );
    },
    onLeave(retval) {
      console.log("[RET producer 0x202] retval=" + (retval.toInt32() & 1));
    }
  });

  Interceptor.attach(mod.base.add(0x55a950), {
    onEnter(args) {
      const sp = this.context.sp;
      console.log(
        "[STORE producer 0x202] " +
        "before STK[0x202]=" + u8(sp, 0x202) + " " +
        "w8=" + (this.context.x8.toInt32() & 1)
      );
    },
    onLeave(retval) {
      const sp = this.context.sp;
      console.log("[AFTER STORE 0x202] STK[0x202]=" + u8(sp, 0x202));
    }
  });

  Interceptor.attach(mod.base.add(0x55c3dc), {
    onEnter(args) {
      console.log("[+] HIT fail_tbz");
    }
  });

  console.log("[+] live 0x202 tracer installed");
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
