const libName = "libnative_level_4.so";
const probeOffset = 0x206b0; // first XOR-call region from count_xors.py
let dumped = false;

function hook() {
  let mod;
  try {
    mod = Process.getModuleByName(libName);
  } catch (e) {
    setTimeout(hook, 250);
    return;
  }

  const probe = mod.base.add(probeOffset);
  console.log("[+] probe:", probe);

  Interceptor.attach(probe, {
    onEnter(args) {
      if (dumped) return;
      dumped = true;

      const x8 = this.context.x8;
      console.log("[+] x8 workbuf:", x8);

      const len = 0x2000;
      const bytes = x8.readByteArray(len);
      send({ type: "workbuf", ptr: x8.toString(), len: len }, bytes);
    }
  });
}

hook();
