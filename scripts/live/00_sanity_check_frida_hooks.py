import frida
import subprocess
import time
import json

APP_NAME = "native level 4"
PKG = "com.example.native_simple"
LIB_NAME = "libnative_level_4.so"

SCRIPT = r"""
const libName = "%s";
const offsets = [0x205f8, 0x55c3dc, 0x55c3f8];

function install() {
  const mod = Process.findModuleByName(libName);
  if (!mod) {
    console.log("[!] no module yet");
    setTimeout(install, 100);
    return;
  }

  console.log("[+] module base: " + mod.base);

  for (const off of offsets) {
    const addr = mod.base.add(off);
    Interceptor.attach(addr, {
      onEnter(args) {
        console.log("[HIT] 0x" + off.toString(16));
        send({type: "hit", off: off});
      }
    });
    console.log("[+] hooked 0x" + off.toString(16));
  }

  send({type: "ready"});
}

install();
""" % LIB_NAME

def adb(*args):
    print("[adb]", " ".join(args))
    return subprocess.run(["adb", *args], text=True)

adb("shell", "am", "force-stop", PKG)
time.sleep(0.3)
adb("shell", "monkey", "-p", PKG, "-c", "android.intent.category.LAUNCHER", "1")
time.sleep(1.0)

device = frida.get_usb_device(timeout=5)
session = device.attach(APP_NAME)
script = session.create_script(SCRIPT)

def on_message(message, data):
    print(message)

script.on("message", on_message)
script.load()

time.sleep(1.0)

adb("shell", "input", "tap", "540", "310")
time.sleep(0.2)
adb("shell", "input", "text", "0000000000000000000000000000000000000000000000000000000000000000")
time.sleep(0.3)
adb("shell", "input", "tap", "540", "520")

print("[+] waiting 5s")
time.sleep(20)
