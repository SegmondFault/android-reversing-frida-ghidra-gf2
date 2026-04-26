const libName = "libnative_level_4.so";
const bpbOffset = 0x200c8;

function hook() {
  let mod;

  try {
    mod = Process.getModuleByName(libName);
  } catch (e) {
    console.log("[-] lib not loaded yet, retrying...");
    setTimeout(hook, 250);
    return;
  }

  const base = mod.base;
  const bpb = base.add(bpbOffset);

  console.log("[+] lib base:", base);
  console.log("[+] _Z1bPb:", bpb);

  Interceptor.attach(bpb, {
    onEnter(args) {
      this.buf = args[0];
      console.log("[>] _Z1bPb buf:", this.buf);

      const len = 0x1000;
      const bytes = Memory.readByteArray(this.buf, len);
      const path = "/data/local/tmp/bpb_seed.bin";

      const f = new File(path, "wb");
      f.write(bytes);
      f.flush();
      f.close();

      console.log("[+] dumped", len, "bytes to", path);
      console.log("[+] first 128 bytes:");
      console.log(hexdump(this.buf, { length: 128, ansi: false }));

      console.log("[+] around 0xc00:");
      console.log(hexdump(this.buf.add(0xc00), { length: 0x120, ansi: false }));

      console.log("[+] around 0xe00:");
      console.log(hexdump(this.buf.add(0xe00), { length: 0x120, ansi: false }));
    },

    onLeave(retval) {
      console.log("[<] _Z1bPb returned:", retval.toInt32());
    }
  });
}

hook();
