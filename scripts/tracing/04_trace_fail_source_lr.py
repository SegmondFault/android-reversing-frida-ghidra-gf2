import frida
import subprocess
import time
import json
import sys

APP_NAME = "native level 4"
PKG = "com.example.native_simple"
LIB_NAME = "libnative_level_4.so"

CANDIDATE = "0011100000111010000000010101000000000000000000000000000000000000"

SCRIPT = r"""
const libName = "%s";

function install() {
  const mod = Process.findModuleByName(libName);
  if (!mod) {
    setTimeout(install, 100);
    return;
  }

  console.log("[+] module base: " + mod.base);

  Interceptor.attach(mod.base.add(0x55c3dc), {
    onEnter(args) {
      const sp = this.context.sp;
      const pc = this.context.pc;
      const lr = this.context.lr;
      const rel_lr = ptr(lr).sub(mod.base);
      const rel_pc = ptr(pc).sub(mod.base);

      console.log("[FAIL]");
      console.log("  pc=" + pc + " rel_pc=0x" + rel_pc.toString(16));
      console.log("  lr=" + lr + " rel_lr=0x" + rel_lr.toString(16));
      console.log("  x0=" + this.context.x0 + " x8=" + this.context.x8 + " x9=" + this.context.x9);

      let s = "";
      for (let off = 0x140; off < 0x161; off++) {
        try {
          s += "0x" + off.toString(16) + "=" + (sp.add(off).readU8() & 1) + " ";
        } catch (e) {
          s += "0x" + off.toString(16) + "=ERR ";
        }
      }
      console.log("[STACK] " + s);

      send({
        type: "fail",
        rel_lr: "0x" + rel_lr.toString(16),
        rel_pc: "0x" + rel_pc.toString(16)
      });
    }
  });

  console.log("[+] fail source tracer installed");
  send({type: "ready"});
}

install();
""" % LIB_NAME


def adb(*args):
    return subprocess.run(["adb", *args], check=False, text=True)


def main():
    adb("shell", "am", "force-stop", PKG)
    adb("shell", "pm", "clear", PKG)
    time.sleep(0.5)
    adb("shell", "monkey", "-p", PKG, "-c", "android.intent.category.LAUNCHER", "1")
    time.sleep(1.5)

    device = frida.get_usb_device(timeout=5)
    session = device.attach(APP_NAME)
    script = session.create_script(SCRIPT)

    def on_message(message, data):
        print(message)

    script.on("message", on_message)
    script.load()

    time.sleep(1.0)

    adb("shell", "input", "tap", "540", "310")
    time.sleep(0.3)
    adb("shell", "input", "text", CANDIDATE)
    time.sleep(0.5)
    adb("shell", "input", "tap", "540", "520")

    print("[+] waiting")
    time.sleep(5)


if __name__ == "__main__":
    main()
