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

  Interceptor.attach(mod.base.add(0x55bdcc), {
    onEnter(args) {
      const sp = this.context.sp;
      console.log("[MASK before 0x15e store] sp+0x138 u8=" + sp.add(0x138).readU8() +
                  " u32=" + sp.add(0x138).readU32() +
                  " u64=" + sp.add(0x138).readU64());
    }
  });

  Interceptor.attach(mod.base.add(0x55c3dc), {
    onEnter(args) {
      console.log("[+] HIT fail_tbz");
    }
  });

  console.log("[+] mask tracer installed");
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
