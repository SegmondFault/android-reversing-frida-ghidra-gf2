import frida, subprocess, time

APP_NAME = "native level 4"
PKG = "com.example.native_simple"
LIB_NAME = "libnative_level_4.so"
CANDIDATE = "0011100000111010000000010101000000000000000000000000000000000000"

SCRIPT = r"""
const libName = "%s";

function install() {
  const mod = Process.findModuleByName(libName);
  if (!mod) { setTimeout(install, 100); return; }

  console.log("[+] module base: " + mod.base);

  Interceptor.attach(mod.base.add(0x55c3cc), {
    onEnter(args) {
      const sp = this.context.sp;
      console.log("[SUCCESS_COPY] sp=" + sp + " lr=" + this.context.lr +
        " sp+0xc=" + sp.add(0xc).readU32() +
        " sp+0x13c=" + sp.add(0x13c).readU32() +
        " sp+0x144=" + (sp.add(0x144).readU8() & 1));
    }
  });

  Interceptor.attach(mod.base.add(0x55c3dc), {
    onEnter(args) {
      const sp = this.context.sp;
      console.log("[EPILOGUE] sp=" + sp + " lr=" + this.context.lr +
        " sp+0xc=" + sp.add(0xc).readU32() +
        " sp+0x13c=" + sp.add(0x13c).readU32() +
        " w8=" + this.context.w8);
    }
  });

  send({type:"ready"});
}
install();
""" % LIB_NAME

def adb(*args):
    return subprocess.run(["adb", *args], check=False, text=True)

adb("shell", "am", "force-stop", PKG)
adb("shell", "pm", "clear", PKG)
time.sleep(0.5)
adb("shell", "monkey", "-p", PKG, "-c", "android.intent.category.LAUNCHER", "1")
time.sleep(1.5)

device = frida.get_usb_device(timeout=5)
session = device.attach(APP_NAME)
script = session.create_script(SCRIPT)
script.on("message", lambda m,d: print(m))
script.load()

time.sleep(1)
adb("shell", "input", "tap", "540", "310")
time.sleep(0.3)
adb("shell", "input", "text", CANDIDATE)
time.sleep(0.5)
adb("shell", "input", "tap", "540", "520")
time.sleep(5)
