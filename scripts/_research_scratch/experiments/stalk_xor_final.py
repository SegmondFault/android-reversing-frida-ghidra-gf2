import frida
import sys
import json

APP_NAME = "native level 4"
LIB_NAME = "libnative_level_4.so"

RET_TO_SPOFF = {
    0x55bdc8: 0x15e, 0x55bde8: 0x15d, 0x55be08: 0x15c,
    0x55be28: 0x15b, 0x55be48: 0x15a, 0x55be68: 0x159,
    0x55be88: 0x158, 0x55bea8: 0x157, 0x55bec8: 0x156,
    0x55bee8: 0x155, 0x55bf08: 0x154, 0x55bf28: 0x153,
    0x55bf48: 0x152, 0x55bf68: 0x151, 0x55bf88: 0x150,
    0x55bfa8: 0x14f, 0x55bfc8: 0x14e, 0x55bfe8: 0x14d,
    0x55c008: 0x14c, 0x55c028: 0x14b, 0x55c048: 0x14a,
    0x55c068: 0x149, 0x55c088: 0x148, 0x55c0a8: 0x147,
    0x55c0c8: 0x146, 0x55c0e8: 0x145, 0x55c108: 0x144,
    0x55c128: 0x143, 0x55c148: 0x142,
}

SCRIPT = """
const libName = %s;
const retToSpoff = %s;

function install() {
  const mod = Process.getModuleByName(libName);
  console.log("[+] module base: " + mod.base);

  const xorFunc = mod.base.add(0x5862f0);

  Interceptor.attach(mod.base.add(0x205f8), {
    onEnter(args) {
      console.log("[+] HIT circuit entry, stalking thread " + this.threadId);

      Stalker.follow(this.threadId, {
        events: { call: true, ret: false, exec: false, block: false, compile: false },
        onReceive(events) {
          const parsed = Stalker.parse(events);
          for (const e of parsed) {
            if (e[0] !== "call") continue;

            const target = ptr(e[2]);
            if (!target.equals(xorFunc)) continue;

            const retaddr = ptr(e[1]);
            const retOff = retaddr.sub(mod.base).toUInt32();

            if (String(retOff) in retToSpoff) {
              console.log("[CALL_TO_XOR_FINAL] retOff=0x" + retOff.toString(16) +
                          " spoff=0x" + retToSpoff[String(retOff)].toString(16));
            }
          }
        }
      });
    }
  });

  Interceptor.attach(mod.base.add(0x55c3dc), {
    onEnter(args) {
      console.log("[+] HIT fail_tbz");
    }
  });

  console.log("[+] stalker installed");
}

install();
""" % (json.dumps(LIB_NAME), json.dumps(RET_TO_SPOFF))

def on_message(message, data):
    print(message)

device = frida.get_usb_device(timeout=5)
session = device.attach(APP_NAME)
script = session.create_script(SCRIPT)
script.on("message", on_message)
script.load()

print("[+] Press CHECK now")
sys.stdin.read()
