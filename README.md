# virtual-platform

Reusable, dependency-free virtual platform building blocks in Zig: a bit/byte
utility library, memory-mapped device models, the two firmware table formats a
guest kernel is handed (ACPI and the flattened device tree), and the Linux boot
protocol structures for each architecture.

Extracted from a deterministic RISC-V emulator so the same device models can be
shared with other guests and machine implementations. The models are pure state
machines — `load`/`store` take a runtime access width and never perform I/O of
their own, so a caller can drive them from an instruction decoder, from a
hardware fault handler, or from a test.

## Modules

The package exposes six modules:

| Module | Root | Contents |
|---|---|---|
| `bits` | `src/bits/bits.zig` | Bit-field extract/insert, mask building, alignment and bounds predicates, little-endian readers. |
| `virtual_devices` | `src/virtual_devices/virtual_devices.zig` | `Uart` (16550); the virtio-mmio devices `VirtioBlk`, `VirtioNet`, `VirtioConsole`, `VirtioVsock`, `VirtioRng` and `VirtioBalloon`, all over the shared `virtio_mmio` transport, `virtqueue` mechanics and `packet_fifo`; per-architecture namespaces `riscv.Plic`/`riscv.Clint` and `x86.AcpiPm`/`x86.Ioapic`/`x86.Lapic`. Imports `bits`. |
| `acpi` | `src/acpi/acpi.zig` | Serializes a declarative machine description into ACPI tables: RSDP, RSDT, FADT, MADT and a DSDT encoded from device descriptors. std-only. |
| `fdt` | `src/fdt/fdt.zig` | Flattened device tree (DTB) serializer. std-only. |
| `x86` | `src/x86/x86.zig` | The x86-64 architecture: `registers` (control, model-specific and CPUID bitfields), `paging` (build and walk 4-level page tables over a guest RAM slice), `mmio_decode` (the MOV behind a memory-mapped access). std-only. |
| `linux_boot` | `src/linux_boot/linux_boot.zig` | Linux image headers and boot-protocol structures, namespaced per architecture; `x86.placement` copies a bzImage and its initramfs into guest RAM at addresses the caller gives. |

## Usage

Add the dependency:

```sh
zig fetch --save git+https://github.com/ozencozturk/virtual-platform.git
```

Wire the modules into your build (`build.zig`):

```zig
const vp = b.dependency("virtual_platform", .{});
your_module.addImport("bits", vp.module("bits"));
your_module.addImport("virtual_devices", vp.module("virtual_devices"));
your_module.addImport("acpi", vp.module("acpi"));
```

Then in source:

```zig
const bits = @import("bits");
const devices = @import("virtual_devices");

var uart: devices.Uart = .{};
try uart.store(devices.Uart.THR_DLL, 1, 'H'); // width is a runtime argument

// A store answers what the device must do next: a queue to serve, or a reset.
var disk: devices.VirtioBlk = .{ .disk = image };
switch (try disk.store(0x050, 4, 0)) {
    .notify => |q| disk.service(q, .{ .memory = ram, .base = 0 }),
    else => {},
}

// The console performs no I/O itself; the owner supplies the sink.
const console: devices.VirtioConsole = .{};
_ = console;

// Entropy as a function of a seed and a position, both device state.
var rng: devices.VirtioRng = .{};
rng.reseed(1);

// Writes reach the image on a flush; a cut keeps only what one claimed.
disk.powerCut(0);

// The PM1 block a guest's ACPI implementation needs to start its interpreter.
var pm: devices.x86.AcpiPm = .{};
const power_off = pm.write(4, 0x2000 | (7 << 10)); // a committed sleep transition
_ = power_off;
```

The ACPI serializer takes a machine description and writes the tables into a
guest RAM buffer, returning the RSDP's guest-physical address:

```zig
const acpi = @import("acpi");

const rsdp_gpa = try acpi.build(ram, .{
    .rsdp_gpa = 0xF_0000,
    .oem = .{ .id = "MYVMM ".*, .table_id = "MYVMMTBL".*, .creator_id = "MYVM".* },
    .madt = .{ .lapic_addr = 0xFEE0_0000, .pcat_compat = true, .entries = &.{
        .{ .local_apic = .{ .uid = 0, .apic_id = 0 } },
    } },
    .dsdt = .{ .s5 = .{ .a = 7, .b = 7 } },
});
```

## Testing

```sh
zig build test --summary all
```

Runs the unit tests for all three modules.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgements

Parts of this project were developed with assistance from AI coding tools
(Claude). All code was reviewed and is maintained by the author.
