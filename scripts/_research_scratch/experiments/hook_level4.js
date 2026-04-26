const libName = "libnative_level_4.so";
const exportName = "Java_com_example_native_1simple_MainActivity_checkPassword";

function hook() {
  let mod = null;

  try {
    mod = Process.getModuleByName(libName);
  } catch (e) {
    console.log("[-] library not loaded yet, retrying...");
    setTimeout(hook, 250);
    return;
  }

  const check = mod.findExportByName(exportName);

  if (check === null) {
    console.log("[-] export not found:", exportName);
    console.log("[*] exports containing check:");
    for (const e of mod.enumerateExports()) {
      if (e.name.includes("check") || e.name.includes("Java_com")) {
        console.log(e.name, e.address);
      }
    }
    return;
  }

  console.log("[+] hooked", exportName, "at", check);

  Interceptor.attach(check, {
    onEnter(args) {
      console.log("[>] checkPassword called");
    },
    onLeave(retval) {
      console.log("[<] original return:", retval.toInt32());
      // retval.replace(1); // force success later
    }
  });
}

setTimeout(hook, 500);
