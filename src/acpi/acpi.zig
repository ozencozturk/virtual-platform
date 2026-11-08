const std = @import("std");
const builtin = @import("builtin");

// An ACPI table serializer. Callers describe the machine with descriptor structs
// — a `Madt` for interrupt topology and a `Dsdt` for the AML device namespace —
// and this module encodes them as bytes: the SDT headers and checksums, the RSDP,
// the RSDT, the FADT, the MADT interrupt-controller structures, and the DSDT's
// AML. Callers never see a raw opcode or a table offset.
//
// The table chain, all placed in the reserved 0xA0000..0x100000 region:
//   RSDP ("RSD PTR ")  — root pointer, found by a scan of 0xE0000..0xFFFFF or by
//                        an address the boot protocol hands the kernel. Points at →
//   RSDT ("RSDT")      — table of 32-bit pointers → { FADT, MADT }.
//   FADT ("FACP")      — fixed-hardware description; points at → DSDT.
//   DSDT ("DSDT")      — AML namespace, encoded from `Dsdt`.
//   MADT ("APIC")      — interrupt topology, encoded from `Madt`.
//
// Every SDT begins with the standard 36-byte header and carries a checksum byte
// chosen so its bytes sum to 0 mod 256; the RSDP has its own 20-byte layout and
// checksum. Pure over the caller's `ram` slice, with no I/O.

/// Guest-physical address.
const Gpa = u64;

// Table lengths derived from the layout structs below. Each of those asserts its
// own size against the ACPI spec number at comptime.
pub const SDT_HDR = @sizeOf(SdtHeader); //          standard ACPI table header (36)
pub const RSDP_LEN = @sizeOf(Rsdp); //              ACPI 1.0 RSDP (20; revision 0 → RSDT)
pub const RSDT_LEN = SDT_HDR + 2 * @sizeOf(u32); // header + two 32-bit table pointers
pub const FADT_LEN = @sizeOf(Fadt); //             ACPI 6.0 FADT (276; revision 6)

// Scratch budgets for the two encoded bodies. The writer bounds-checks every
// append against these, and `build` returns `error.AcpiTooLarge` before writing
// guest RAM when a description does not fit. `DSDT_AML_MAX` also bounds how many
// devices a caller may declare; placement uses the encoded length, so raising it
// costs stack and the reservation bound below and nothing in the tables
// themselves.
const MADT_BODY_MAX = 256;
const DSDT_AML_MAX = 2048;

/// Upper bound on the RSDT/FADT/DSDT/MADT block.
pub const MAX_TABLES_LEN = RSDT_LEN + FADT_LEN + (SDT_HDR + DSDT_AML_MAX) + (SDT_HDR + MADT_BODY_MAX);

/// Upper bound on the whole ACPI footprint from `rsdp_gpa` — the RSDP plus the
/// table block that follows it. What a caller's static layout guard checks against.
pub const MAX_FOOTPRINT = RSDP_LEN + MAX_TABLES_LEN;

/// Where the RSDT/FADT/DSDT/MADT block starts, given the RSDP's address: directly
/// after it. Every other table position is derived by chaining from here
/// (fadt → dsdt → madt). Exposed so layout guards and tests compute it the same
/// way `build` does.
pub fn tablesGpa(rsdp_gpa: Gpa) Gpa {
    return rsdp_gpa + RSDP_LEN;
}

// ---- declarative machine description (what the caller provides) ------------

/// The MPS INTI flags word shared by the MADT structures that describe how an
/// interrupt line is wired (ACPI spec §5.2.12, "MPS INTI Flags"). Two 2-bit enums
/// in the low nibble; the rest reserved. `conforms` means "whatever the bus
/// specification says", which is the spec's default for both fields.
pub const MpsIntiFlags = packed struct(u16) {
    polarity: Polarity = .conforms, // 0..1
    trigger: Trigger = .conforms, //   2..3
    _rsvd: u12 = 0, //                 4..15

    // Both are non-exhaustive: value 2 is reserved in each field.
    pub const Polarity = enum(u2) { conforms = 0, active_high = 1, active_low = 3, _ };
    pub const Trigger = enum(u2) { conforms = 0, edge = 1, level = 3, _ };

    pub fn toBits(self: MpsIntiFlags) u16 {
        return @bitCast(self);
    }

    comptime {
        // Pins the field positions: active-high + edge is the conventional 0x0005.
        std.debug.assert((MpsIntiFlags{ .polarity = .active_high, .trigger = .edge }).toBits() == 0x0005);
        std.debug.assert((MpsIntiFlags{ .trigger = .level }).toBits() == 0x000C);
    }
};

/// One MADT interrupt-controller structure. The encoder lays out the exact ACPI
/// bytes for each variant; the caller only states the facts.
pub const MadtEntry = union(enum) {
    /// Type 0: Processor Local APIC.
    local_apic: struct { uid: u8, apic_id: u8, enabled: bool = true },
    /// Type 1: I/O APIC.
    io_apic: struct { id: u8, addr: u32, gsi_base: u32 = 0 },
    /// Type 4: Local APIC NMI (which LINT pin is wired to NMI, on which processors).
    local_apic_nmi: struct { uid: u8, flags: MpsIntiFlags, lint: u8 },
};

/// The interrupt topology: the Local APIC address, the PCAT_COMPAT flag (a legacy
/// dual-8259 is present), and the interrupt-controller structures.
pub const Madt = struct {
    lapic_addr: u32,
    pcat_compat: bool,
    entries: []const MadtEntry,
};

/// Whether a device's MMIO window accepts writes: Memory32Fixed's write-status
/// bit. Values outside the two named ones are refused by `build`.
pub const MemoryAccess = enum(u8) {
    read_only = 0,
    read_write = 1,
    _,
};

/// One AML device object placed under \_SB: a _HID, a _UID, and a _CRS
/// describing exactly one fixed MMIO window and, when `irq` is set, one
/// edge-triggered, active-high interrupt. An explicit `irq = 0` is interrupt 0,
/// not an absent one. A device needing a different resource shape needs the
/// descriptor widened first.
pub const AmlDevice = struct {
    name: [4]u8, //        ACPI name segment, e.g. "VR00".*
    hid: []const u8, //    _HID value, e.g. "LNRO0005"
    uid: u32 = 0,
    mmio_base: u32,
    mmio_size: u32,
    irq: ?u32 = null,
    memory_access: MemoryAccess = .read_write,
};

/// Why `build` refused a description. Nothing is written to guest RAM when it
/// returns one of these.
pub const BuildError = error{
    /// A table address, the RAM bound, or a 32-bit table pointer does not fit.
    AcpiOutOfRange,
    /// An encoded body, resource or package length exceeds its fixed budget.
    AcpiTooLarge,
    /// A device has an invalid name, _HID, window or access value, or two
    /// devices in \_SB share a name (including the generation-ID devices).
    InvalidAcpiDevice,
};

/// The sleep-type values the \_S5 object publishes — what ACPICA writes into the
/// PM1 control registers' SLP_TYP field to enter soft off. These are *chipset*
/// defined rather than fixed by the ACPI spec, which is what \_S5 exists to
/// publish. The `u3` width is PM1_CONTROL's SLP_TYP field, so a value that could
/// not round-trip through that register is not representable.
pub const SleepType = struct {
    a: u3, //  → PM1a_CNT.SLP_TYP
    b: u3, //  → PM1b_CNT.SLP_TYP (ignored when there is no PM1b block, as here)
};

/// The DSDT's AML namespace: the devices under \_SB and, optionally, an \_S5
/// soft-off object (its presence is what makes Linux register pm_power_off).
pub const Dsdt = struct {
    devices: []const AmlDevice = &.{},
    s5: ?SleepType = null,
    generation_id: ?GenerationId = null,
};

/// A VM Generation ID device (Microsoft's Virtual Machine Generation ID
/// specification) under \_SB: VGEN (_HID "VMGENCTR") publishes the address of a
/// 16-byte ID in ADDR, and a Generic Event Device, GED0 (_HID "ACPI0013"),
/// runs Notify(\_SB.VGEN, 0x80) when its interrupt fires. The owner of the ID
/// raises that interrupt after it changes the ID.
pub const GenerationId = struct {
    addr: u64, //       GPA of the 16-byte generation ID
    event_irq: u32, //  GSI GED0 consumes (edge, active-high)
};

/// Identity stamped into the RSDP and into every table header. ACPI fixes the
/// widths; names shorter than the field are padded with spaces.
pub const Oem = struct {
    id: [6]u8,
    table_id: [8]u8,
    revision: u32 = 1,
    creator_id: [4]u8,
    creator_revision: u32 = 1,
};

pub const Params = struct {
    rsdp_gpa: Gpa, //     Where to place the RSDP. Must be somewhere a guest
    //                    will look — conventionally inside the 0xE0000..0xFFFFF
    //                    scan window. The RSDT/FADT/DSDT/MADT block follows it,
    //                    see tablesGpa.

    /// Who the tables claim to come from.
    oem: Oem,

    // --- fixed-hardware description ---
    // PM1a event and control block I/O ports, and the length of each in bytes.
    // A zero port means the block is absent, and its length is then emitted as
    // zero whatever is passed here; an ACPICA-based guest with no PM1a block
    // leaves its interpreter disabled and enumerates no ACPI devices. The
    // lengths belong to whatever models the registers, so they are supplied
    // rather than assumed. `sci_int` is the SCI's GSI.
    pm1a_evt_blk: u16 = 0,
    pm1a_cnt_blk: u16 = 0,
    pm1a_evt_len: u8 = 0,
    pm1a_cnt_len: u8 = 0,
    sci_int: u16 = 0,
    // RESET_REG: an I/O port the guest writes `reset_value` to for an ACPI reboot.
    // 0 ⇒ no reset register (flag/GAS/value stay zero).
    reset_reg: u16 = 0,
    reset_value: u8 = 0,

    // --- declarative table descriptions (this module serializes them) ---
    madt: Madt,
    dsdt: Dsdt,
};

/// Write the RSDP (at rsdp_gpa) and the RSDT/FADT/DSDT/MADT block that follows it
/// into `ram`. GPAs are direct offsets (RAM is mapped from GPA 0), so the values
/// written into the tables are the GPAs themselves. Returns the RSDP GPA, which
/// a boot protocol can hand to the kernel directly.
///
/// Every check runs before the first write: an error leaves `ram` unchanged.
pub fn build(ram: []u8, p: Params) BuildError!Gpa {
    try validateDsdt(p.dsdt);

    // Encode the two variable-length bodies up front, so their placed lengths are
    // known before the layout is fixed.
    var madt_scratch: [MADT_BODY_MAX]u8 = undefined;
    var mb = Buf{ .data = &madt_scratch };
    try encodeMadt(&mb, p.madt);
    const madt_body = mb.used();

    var aml_scratch: [DSDT_AML_MAX]u8 = undefined;
    var ab = Buf{ .data = &aml_scratch };
    try encodeDsdt(&ab, p.dsdt);
    const dsdt_aml = ab.used();

    const dsdt_len = SDT_HDR + dsdt_aml.len;
    const madt_len = SDT_HDR + madt_body.len;

    // Layout: the RSDP first, then the tables back-to-back after it. Their
    // cross-references are absolute GPAs, known before any write. The RSDT and
    // RSDP hold 32-bit pointers, so every table must start below 4 GiB.
    const rsdp_end = std.math.add(Gpa, p.rsdp_gpa, RSDP_LEN) catch return error.AcpiOutOfRange;
    const rsdt_gpa = rsdp_end; // tablesGpa(p.rsdp_gpa), overflow-checked
    const fadt_gpa = std.math.add(Gpa, rsdt_gpa, RSDT_LEN) catch return error.AcpiOutOfRange;
    const dsdt_gpa = std.math.add(Gpa, fadt_gpa, FADT_LEN) catch return error.AcpiOutOfRange;
    const madt_gpa = std.math.add(Gpa, dsdt_gpa, dsdt_len) catch return error.AcpiOutOfRange;
    const tables_end = std.math.add(Gpa, madt_gpa, madt_len) catch return error.AcpiOutOfRange;

    if (rsdp_end > ram.len) return error.AcpiOutOfRange;
    if (tables_end > ram.len) return error.AcpiOutOfRange;
    if (madt_gpa > std.math.maxInt(u32)) return error.AcpiOutOfRange;

    // --- RSDT: a body of 32-bit pointers to the FADT and MADT ---
    {
        var rsdt_body: [2 * @sizeOf(u32)]u8 = undefined;
        var rb = Buf{ .data = &rsdt_body };
        // Two dwords into an eight-byte buffer, both pointers checked below 4 GiB.
        rb.dword(@intCast(fadt_gpa)) catch unreachable;
        rb.dword(@intCast(madt_gpa)) catch unreachable;
        _ = writeTable(ram, rsdt_gpa, p.oem, "RSDT", 1, rb.used());
    }

    // --- FADT: fixed-hardware description, points at the DSDT ---
    {
        var f = std.mem.zeroes(Fadt);
        f.header = initHeader(p.oem, "FACP", FADT_LEN, 6); // revision 6 → ACPI 6.x, X_DSDT honored
        // firmware_ctrl = 0: no FACS (optional — only needed to sleep).
        f.dsdt = @intCast(dsdt_gpa);
        f.x_dsdt = dsdt_gpa; // 64-bit form (honored at revision 6)
        // smi_cmd = 0 with acpi_enable/disable = 0 is the spec's "no SMM, already
        // in ACPI mode", which skips the SMI enable handshake. ACPICA synthesizes
        // the X_ GAS forms from these legacy 32-bit fields and their lengths.
        // PM2, PM_TMR and GPE stay zero: unused, and no GPEs are raised.
        f.sci_int = p.sci_int;
        f.pm1a_evt_blk = p.pm1a_evt_blk;
        f.pm1a_cnt_blk = p.pm1a_cnt_blk;
        f.pm1_evt_len = if (p.pm1a_evt_blk != 0) p.pm1a_evt_len else 0;
        f.pm1_cnt_len = if (p.pm1a_cnt_blk != 0) p.pm1a_cnt_len else 0;
        // Flags: NOT hardware-reduced — a legacy PC with an I/O APIC, matching the
        // MADT's PCAT_COMPAT. Bit 10 (RESET_REG_SUP) advertises the reset register
        // below; set only when a reset port was given.
        if (p.reset_reg != 0) {
            f.flags = 1 << 10; //                          RESET_REG_SUP
            // A Generic Address Structure — SystemIO, 8-bit, at the reset port;
            // reset_value is the byte the guest writes to it.
            f.reset_reg = .{ .space = 1, .bit_width = 8, .bit_offset = 0, .access_size = 1, .address = p.reset_reg };
            f.reset_value = p.reset_value;
        }
        // Tell the kernel there is no CMOS RTC *device*, while still answering
        // its ports.
        //
        // Without this, `add_rtc_cmos()` finds no PNP node, falls back to a
        // default platform device, and assumes the real chip's resources —
        // including IRQ 8. Linux then advertises "alarms up to one day" on an
        // alarm nothing can deliver: the emulated clock is frozen at a fixed
        // epoch, so the alarm registers can never match, and a guest setting one
        // (rtcwake, /sys/class/rtc/rtc0/wakealarm) waits forever.
        //
        // This suppresses only that platform device. `read_persistent_clock64`
        // -> `mach_get_cmos_time` still reads ports 0x70/0x71 directly, so a CMOS
        // RTC model behind those ports still seeds the guest's wall clock.
        f.iapc_boot_arch = .{ .cmos_rtc_not_present = true };
        f.header.checksum = checksum(std.mem.asBytes(&f));
        @memcpy(ram[@intCast(fadt_gpa)..][0..FADT_LEN], std.mem.asBytes(&f));
    }

    // --- DSDT: standard header + the encoded AML namespace ---
    _ = writeTable(ram, dsdt_gpa, p.oem, "DSDT", 2, dsdt_aml);

    // --- MADT: standard header + the encoded interrupt-topology body ---
    _ = writeTable(ram, madt_gpa, p.oem, "APIC", 4, madt_body);

    // --- RSDP: written last; points at the RSDT. Placed inside the legacy
    // 0xE0000..0xFFFFF scan window, so a scanning kernel finds it whether or not
    // it was also given the address directly. ---
    {
        var r = Rsdp{
            .signature = "RSD PTR ".*,
            .checksum = 0,
            .oem_id = p.oem.id,
            .revision = 0, //              ACPI 1.0 → use the 32-bit RsdtAddress
            .rsdt_address = @intCast(rsdt_gpa),
        };
        r.checksum = checksum(std.mem.asBytes(&r)); // first-20-bytes checksum (ACPI 1.0)
        @memcpy(ram[@intCast(p.rsdp_gpa)..][0..RSDP_LEN], std.mem.asBytes(&r));
    }

    return p.rsdp_gpa;
}

// ---- MADT body encoding ----------------------------------------------------

// The wire layout of each MADT interrupt-controller structure (ACPI spec §5.2.12).
// Each carries its own ACPI type/length as struct defaults, and the comptime assert
// pins its byte length against the spec — the same guard the FADT/RSDP structs use.
// `flags` in the NMI record sits at offset 3 (unaligned), so it is `align(1)`.
const IcsLocalApic = extern struct { //     type 0: Processor Local APIC
    type: u8 = 0,
    length: u8 = 8,
    uid: u8,
    apic_id: u8,
    flags: u32 align(1),
    comptime {
        std.debug.assert(@sizeOf(IcsLocalApic) == 8);
    }
};
const IcsIoApic = extern struct { //        type 1: I/O APIC
    type: u8 = 1,
    length: u8 = 12,
    id: u8,
    reserved: u8 = 0,
    addr: u32 align(1),
    gsi_base: u32 align(1),
    comptime {
        std.debug.assert(@sizeOf(IcsIoApic) == 12);
    }
};
const IcsLocalApicNmi = extern struct { //  type 4: Local APIC NMI
    type: u8 = 4,
    length: u8 = 6,
    uid: u8,
    flags: MpsIntiFlags align(1),
    lint: u8,
    comptime {
        std.debug.assert(@sizeOf(IcsLocalApicNmi) == 6);
    }
};

/// Encode the MADT body (everything after the SDT header): the Local APIC address,
/// the MADT flags, then each interrupt-controller structure.
fn encodeMadt(dst: *Buf, m: Madt) Overflow!void {
    try dst.dword(m.lapic_addr); //                Local APIC address
    try dst.dword(if (m.pcat_compat) 1 else 0); // Flags: bit 0 = PCAT_COMPAT
    for (m.entries) |e| switch (e) {
        .local_apic => |a| try dst.slice(std.mem.asBytes(&IcsLocalApic{
            .uid = a.uid,
            .apic_id = a.apic_id,
            .flags = if (a.enabled) 1 else 0, // Enabled
        })),
        .io_apic => |a| try dst.slice(std.mem.asBytes(&IcsIoApic{
            .id = a.id,
            .addr = a.addr,
            .gsi_base = a.gsi_base,
        })),
        .local_apic_nmi => |a| try dst.slice(std.mem.asBytes(&IcsLocalApicNmi{
            .uid = a.uid, //                     0xFF = all processors
            .flags = a.flags, //                 MPS INTI flags
            .lint = a.lint, //                   LINT#
        })),
    };
}

// ---- DSDT / AML encoding ---------------------------------------------------
//
// A minimal AML encoder — only the constructs these tables use: Scope, Device,
// Name, integers, a _CRS ResourceTemplate (Memory32Fixed + Extended Interrupt),
// and a Package. PkgLength is emitted in its minimal ACPI form (1 byte for lengths
// ≤ 0x3F, otherwise 2 bytes). See ACPI spec §20.2.

/// AML opcodes and resource-descriptor tags (ACPI spec §20.2.x / §6.4.3).
const Aml = struct {
    const zero = 0x00; //             ZeroOp (integer 0)
    const one = 0x01; //              OneOp (integer 1)
    const name_op = 0x08; //          Name(NameString, DataObject)
    const byte_prefix = 0x0A; //      BytePrefix (u8 constant follows)
    const word_prefix = 0x0B; //      WordPrefix (u16 constant follows)
    const dword_prefix = 0x0C; //     DWordPrefix (u32 constant follows)
    const string_prefix = 0x0D; //    StringPrefix (NUL-terminated ASCII follows)
    const scope_op = 0x10; //         Scope(NameString){ ... }
    const buffer_op = 0x11; //        Buffer(Size){ bytes }
    const package_op = 0x12; //       Package(N){ elements }
    const ext_op_prefix = 0x5B; //    extended-opcode escape
    const device_op = 0x82; //        Device(NameString){ ... } — follows ext_op_prefix
    const method_op = 0x14; //        Method(NameString, flags){ ... }
    const notify_op = 0x86; //        Notify(SuperName, Value)
    const dual_name_prefix = 0x2E; // two name segments follow
    const root_char = 0x5C; //        '\' root prefix in a NameString
    // Large resource-descriptor tags inside a _CRS ResourceTemplate:
    const memory32_fixed = 0x86; //   Memory32Fixed(RW, base, length)
    const extended_interrupt = 0x89; //Extended Interrupt(flags, count, irq...)
    const end_tag = 0x79; //          End Tag (closes a ResourceTemplate)
};

/// Memory32Fixed's information byte (ACPI spec §6.4.3.4). Only the write-status bit
/// is defined; everything above it is reserved.
const Memory32Flags = packed struct(u8) {
    write_ok: bool = false, // 0  1 = read/write, 0 = read-only
    _rsvd: u7 = 0, //          1..7

    fn toBits(self: Memory32Flags) u8 {
        return @bitCast(self);
    }
};

/// The Extended Interrupt descriptor's flags byte (ACPI spec §6.4.3.6). NOTE: this
/// is a *different* encoding from the MADT's MpsIntiFlags — same physical wiring
/// described by another table, with its fields in other positions and opposite
/// polarity sense (here 1 = active LOW). A separate type so the two cannot be
/// swapped.
const ExtIntFlags = packed struct(u8) {
    consumer: bool = false, //    0  1 = this device consumes the interrupt
    edge: bool = false, //        1  1 = edge-triggered, 0 = level
    active_low: bool = false, //  2  1 = active low, 0 = active high
    shared: bool = false, //      3  1 = shared, 0 = exclusive
    wake_capable: bool = false, //4  1 = can wake the system
    _rsvd: u3 = 0, //             5..7

    fn toBits(self: ExtIntFlags) u8 {
        return @bitCast(self);
    }
};

comptime {
    // Pin both against the values the hand-encoded descriptors used before.
    std.debug.assert((Memory32Flags{ .write_ok = true }).toBits() == 0x01);
    std.debug.assert((ExtIntFlags{ .consumer = true, .edge = true }).toBits() == 0x03);
}

/// Refuse a namespace the encoder would emit wrongly: an invalid name segment,
/// _HID or window, an unknown access value, or two siblings in \_SB sharing a
/// name, counting the VGEN/GED0 pair the generation ID adds.
fn validateDsdt(d: Dsdt) error{InvalidAcpiDevice}!void {
    for (d.devices, 0..) |dev, i| {
        if (!validNameSeg(dev.name)) return error.InvalidAcpiDevice;
        if (!validHid(dev.hid)) return error.InvalidAcpiDevice;
        if (dev.mmio_size == 0) return error.InvalidAcpiDevice;
        if (@as(u64, dev.mmio_base) + dev.mmio_size > 0x1_0000_0000) return error.InvalidAcpiDevice;
        switch (dev.memory_access) {
            .read_only, .read_write => {},
            _ => return error.InvalidAcpiDevice,
        }
        for (d.devices[0..i]) |prev| {
            if (std.mem.eql(u8, &prev.name, &dev.name)) return error.InvalidAcpiDevice;
        }
        if (d.generation_id != null) {
            if (std.mem.eql(u8, &dev.name, "VGEN") or std.mem.eql(u8, &dev.name, "GED0"))
                return error.InvalidAcpiDevice;
        }
    }
}

/// An AML NameSeg: a lead character from A-Z or '_', then A-Z, 0-9 or '_'.
fn validNameSeg(name: [4]u8) bool {
    for (name, 0..) |c, i| {
        const ok = (c >= 'A' and c <= 'Z') or c == '_' or (i > 0 and c >= '0' and c <= '9');
        if (!ok) return false;
    }
    return true;
}

/// A _HID string: nonempty printable ASCII with no space, so the NUL-terminated
/// AML string carries it unchanged.
fn validHid(hid: []const u8) bool {
    if (hid.len == 0) return false;
    for (hid) |c| if (c < 0x21 or c > 0x7E) return false;
    return true;
}

/// Encode the whole DSDT AML body: Scope(\_SB){ devices... } followed by an
/// optional top-level Name(\_S5, Package).
fn encodeDsdt(dst: *Buf, d: Dsdt) Overflow!void {
    // Scope(\_SB) { device objects }
    var body: [DSDT_AML_MAX]u8 = undefined;
    var b = Buf{ .data = &body };
    try b.byte(Aml.root_char); //  '\'
    try b.slice("_SB_"); //        name segment
    for (d.devices) |dev| try encodeDevice(&b, dev);
    if (d.generation_id) |g| try encodeGenerationId(&b, g);
    try dst.byte(Aml.scope_op);
    try pkgLength(dst, b.len);
    try dst.slice(b.used());

    // Name(\_S5, Package(4){ SLP_TYPa, SLP_TYPb, 0, 0 }) — a sibling of the scope.
    if (d.s5) |s5| {
        var pkg: [16]u8 = undefined;
        var p = Buf{ .data = &pkg };
        try p.byte(4); //          NumElements
        try integer(&p, s5.a); //  SLP_TYPa
        try integer(&p, s5.b); //  SLP_TYPb
        try integer(&p, 0); //     reserved (spec: ignored)
        try integer(&p, 0); //     reserved
        try dst.byte(Aml.name_op);
        try dst.slice("_S5_");
        try dst.byte(Aml.package_op);
        try pkgLength(dst, p.len);
        try dst.slice(p.used());
    }
}

/// Encode one Device(){ Name(_HID), Name(_UID), Name(_CRS) } under the enclosing
/// scope.
fn encodeDevice(dst: *Buf, dev: AmlDevice) Overflow!void {
    var body: [256]u8 = undefined;
    var b = Buf{ .data = &body };
    try b.slice(&dev.name); //    device name segment

    // Name(_HID, "<string>")
    try b.byte(Aml.name_op);
    try b.slice("_HID");
    try b.byte(Aml.string_prefix);
    try b.slice(dev.hid);
    try b.byte(0x00); //          NUL terminator

    // Name(_UID, <int>)
    try b.byte(Aml.name_op);
    try b.slice("_UID");
    try integer(&b, dev.uid);

    // Name(_CRS, ResourceTemplate(){ ... })
    try b.byte(Aml.name_op);
    try b.slice("_CRS");
    try encodeCrs(&b, dev);

    try dst.byte(Aml.ext_op_prefix);
    try dst.byte(Aml.device_op);
    try pkgLength(dst, b.len);
    try dst.slice(b.used());
}

/// Encode a _CRS value: Buffer(){ Memory32Fixed(access, base, size); and, when the
/// device has one, Interrupt(irq) }. `validateDsdt` has already refused an access
/// value outside the two named ones.
fn encodeCrs(dst: *Buf, dev: AmlDevice) Overflow!void {
    // The raw resource descriptors, sized first so the Buffer length is known.
    var res: [64]u8 = undefined;
    var r = Buf{ .data = &res };
    // Memory32Fixed(access, base, size): tag, body length, info, base u32, len u32.
    try r.byte(Aml.memory32_fixed);
    try r.word(0x0009);
    try r.byte((Memory32Flags{ .write_ok = dev.memory_access == .read_write }).toBits());
    try r.dword(dev.mmio_base);
    try r.dword(dev.mmio_size);
    // Extended Interrupt(Consumer, Edge, ActiveHigh, Exclusive, count=1, irq).
    // active_low/shared stay clear ⇒ active-high, exclusive — matching the MADT's
    // MpsIntiFlags for the same line and the ioapic model's edge delivery.
    if (dev.irq) |irq| {
        try r.byte(Aml.extended_interrupt);
        try r.word(0x0006);
        try r.byte((ExtIntFlags{ .consumer = true, .edge = true }).toBits());
        try r.byte(0x01); //          interrupt count
        try r.dword(irq);
    }
    // End tag + checksum(0).
    try r.byte(Aml.end_tag);
    try r.byte(0x00);

    // Buffer: BufferOp, PkgLength, BufferSize(integer = resource byte count), bytes.
    var sz: [8]u8 = undefined;
    var s = Buf{ .data = &sz };
    try integer(&s, @intCast(r.len));

    try dst.byte(Aml.buffer_op);
    try pkgLength(dst, s.len + r.len);
    try dst.slice(s.used());
    try dst.slice(r.used());
}

/// Encode Device(VGEN){ _HID, _UID, ADDR } and Device(GED0){ _HID, _UID, _CRS, _EVT }.
fn encodeGenerationId(dst: *Buf, g: GenerationId) Overflow!void {
    var vgen: [64]u8 = undefined;
    var v = Buf{ .data = &vgen };
    try v.slice("VGEN");
    try nameString(&v, "_HID", "VMGENCTR");
    try v.byte(Aml.name_op);
    try v.slice("_UID");
    try integer(&v, 0);
    // Name(ADDR, Package(2){ low 32 bits, high 32 bits })
    var pkg: [16]u8 = undefined;
    var p = Buf{ .data = &pkg };
    try p.byte(2);
    try integer(&p, @truncate(g.addr));
    try integer(&p, @intCast(g.addr >> 32));
    try v.byte(Aml.name_op);
    try v.slice("ADDR");
    try v.byte(Aml.package_op);
    try pkgLength(&v, p.len);
    try v.slice(p.used());
    try deviceOf(dst, v.used());

    var ged: [96]u8 = undefined;
    var e = Buf{ .data = &ged };
    try e.slice("GED0");
    try nameString(&e, "_HID", "ACPI0013");
    try e.byte(Aml.name_op);
    try e.slice("_UID");
    try integer(&e, 0);
    try e.byte(Aml.name_op);
    try e.slice("_CRS");
    try encodeInterruptCrs(&e, g.event_irq);
    // Method(_EVT, 1){ Notify(\_SB.VGEN, 0x80) }
    var m: [32]u8 = undefined;
    var mb = Buf{ .data = &m };
    try mb.slice("_EVT");
    try mb.byte(0x01); // MethodFlags: one argument, not serialized
    try mb.byte(Aml.notify_op);
    try mb.byte(Aml.root_char);
    try mb.byte(Aml.dual_name_prefix);
    try mb.slice("_SB_");
    try mb.slice("VGEN");
    try mb.byte(Aml.byte_prefix);
    try mb.byte(0x80);
    try e.byte(Aml.method_op);
    try pkgLength(&e, mb.len);
    try e.slice(mb.used());
    try deviceOf(dst, e.used());
}

/// Wrap an encoded name segment and body in Device(){ ... }.
fn deviceOf(dst: *Buf, body: []const u8) Overflow!void {
    try dst.byte(Aml.ext_op_prefix);
    try dst.byte(Aml.device_op);
    try pkgLength(dst, body.len);
    try dst.slice(body);
}

/// Emit Name(<name>, "<value>").
fn nameString(dst: *Buf, comptime name: *const [4]u8, value: []const u8) Overflow!void {
    try dst.byte(Aml.name_op);
    try dst.slice(name);
    try dst.byte(Aml.string_prefix);
    try dst.slice(value);
    try dst.byte(0x00);
}

/// Encode a _CRS value holding one Extended Interrupt (Consumer, Edge, ActiveHigh, Exclusive).
fn encodeInterruptCrs(dst: *Buf, irq: u32) Overflow!void {
    var res: [16]u8 = undefined;
    var r = Buf{ .data = &res };
    try r.byte(Aml.extended_interrupt);
    try r.word(0x0006);
    try r.byte((ExtIntFlags{ .consumer = true, .edge = true }).toBits());
    try r.byte(0x01); //          interrupt count
    try r.dword(irq);
    try r.byte(Aml.end_tag);
    try r.byte(0x00);
    var sz: [8]u8 = undefined;
    var s = Buf{ .data = &sz };
    try integer(&s, @intCast(r.len));
    try dst.byte(Aml.buffer_op);
    try pkgLength(dst, s.len + r.len);
    try dst.slice(s.used());
    try dst.slice(r.used());
}

/// Emit an AML integer term with the smallest opcode that fits.
fn integer(dst: *Buf, v: u32) Overflow!void {
    switch (v) {
        0 => try dst.byte(Aml.zero),
        1 => try dst.byte(Aml.one),
        else => {
            if (v <= 0xFF) {
                try dst.byte(Aml.byte_prefix);
                try dst.byte(@intCast(v));
            } else if (v <= 0xFFFF) {
                try dst.byte(Aml.word_prefix);
                try dst.word(@intCast(v));
            } else {
                try dst.byte(Aml.dword_prefix);
                try dst.dword(v);
            }
        },
    }
}

/// Emit a minimal AML PkgLength for a package whose content (everything after the
/// PkgLength field) is `content_len` bytes. The encoded length counts itself.
fn pkgLength(dst: *Buf, content_len: usize) Overflow!void {
    if (content_len + 1 <= 0x3F) {
        try dst.byte(@intCast(content_len + 1)); //   1-byte form (lead bits 6-7 = 0)
    } else {
        const total = content_len + 2;
        if (total > 0xFFF) return error.AcpiTooLarge;
        try dst.byte(@intCast(0x40 | (total & 0x0F))); // 1 follow byte
        try dst.byte(@intCast((total >> 4) & 0xFF));
    }
}

// ---- little-endian append writer -------------------------------------------

/// An encoded body that would not fit its fixed scratch buffer.
const Overflow = error{AcpiTooLarge};

const Buf = struct {
    data: []u8,
    len: usize = 0,

    fn room(self: *const Buf, n: usize) Overflow!void {
        if (n > self.data.len - self.len) return error.AcpiTooLarge;
    }
    fn byte(self: *Buf, b: u8) Overflow!void {
        try self.room(1);
        self.data[self.len] = b;
        self.len += 1;
    }
    fn slice(self: *Buf, s: []const u8) Overflow!void {
        try self.room(s.len);
        @memcpy(self.data[self.len..][0..s.len], s);
        self.len += s.len;
    }
    fn word(self: *Buf, v: u16) Overflow!void {
        try self.room(2);
        std.mem.writeInt(u16, self.data[self.len..][0..2], v, .little);
        self.len += 2;
    }
    fn dword(self: *Buf, v: u32) Overflow!void {
        try self.room(4);
        std.mem.writeInt(u32, self.data[self.len..][0..4], v, .little);
        self.len += 4;
    }
    fn used(self: *const Buf) []const u8 {
        return self.data[0..self.len];
    }
};

// ---- standard SDT header + checksum ----------------------------------------

/// The standard 36-byte ACPI System Description Table header. ACPI is
/// little-endian, so on a little-endian host the struct is written straight to
/// guest memory with no byte-swap. The comptime asserts pin both invariants: the
/// C-ABI layout packs to exactly SDT_HDR bytes, and the host is little-endian.
const SdtHeader = extern struct {
    signature: [4]u8,
    length: u32,
    revision: u8,
    checksum: u8, //          patched by the caller once the body is laid down
    oem_id: [6]u8,
    oem_table_id: [8]u8,
    oem_revision: u32,
    creator_id: [4]u8,
    creator_revision: u32,

    comptime {
        std.debug.assert(@sizeOf(SdtHeader) == 36); // ACPI: 36-byte SDT header
        std.debug.assert(builtin.cpu.arch.endian() == .little);
    }
};

/// An ACPI Generic Address Structure (12 bytes). `address` is a 64-bit field at
/// offset 4 — unaligned — so it is `align(1)`; the whole GAS is byte-packed, which
/// the SdtHeader/Fadt asserts transitively pin.
const Gas = extern struct {
    space: u8, //         address space id (1 = SystemIO)
    bit_width: u8,
    bit_offset: u8,
    access_size: u8, //   1 = byte
    address: u64 align(1),
};

/// The ACPI 1.0 Root System Description Pointer (20 bytes). All fields are
/// naturally aligned, so no `align(1)` is needed; the assert pins the layout.
const Rsdp = extern struct {
    signature: [8]u8, // "RSD PTR " (note the trailing space)
    checksum: u8, //     first-20-bytes checksum (patched last)
    oem_id: [6]u8,
    revision: u8, //     0 → ACPI 1.0, use the 32-bit RsdtAddress
    rsdt_address: u32,

    comptime {
        std.debug.assert(@sizeOf(Rsdp) == 20); // ACPI 1.0: 20-byte RSDP
    }
};

/// FADT IAPC_BOOT_ARCH (ACPI 6.x, table 5.10): what IA-PC legacy hardware the
/// firmware is telling the OS to expect.
const IapcBootArch = packed struct(u16) {
    legacy_devices: bool = false, //        0
    i8042: bool = false, //                 1
    vga_not_present: bool = false, //       2
    msi_not_supported: bool = false, //     3
    pcie_aspm_controls: bool = false, //    4
    cmos_rtc_not_present: bool = false, //  5
    _rsvd6: u10 = 0,
};

/// The ACPI 6.0 Fixed ACPI Description Table (276 bytes). This is a `#pragma
/// pack(1)` structure — every multi-byte field past the header is byte-packed and
/// many 64-bit fields sit at unaligned offsets (e.g. `x_dsdt` at 140), so they are
/// all `align(1)`. The comptime assert pins the exact 276-byte ACPI layout: a
/// mis-sized or misordered field fails the build.
const Fadt = extern struct {
    header: SdtHeader,
    firmware_ctrl: u32 align(1), // @36  FACS (32-bit); 0 = none
    dsdt: u32 align(1), //         @40  DSDT (32-bit)
    reserved1: u8, //              @44
    pm_profile: u8, //             @45
    sci_int: u16 align(1), //      @46
    smi_cmd: u32 align(1), //      @48
    acpi_enable: u8, //            @52
    acpi_disable: u8, //           @53
    s4bios_req: u8, //             @54
    pstate_cnt: u8, //             @55
    pm1a_evt_blk: u32 align(1), // @56
    pm1b_evt_blk: u32 align(1), // @60
    pm1a_cnt_blk: u32 align(1), // @64
    pm1b_cnt_blk: u32 align(1), // @68
    pm2_cnt_blk: u32 align(1), //  @72
    pm_tmr_blk: u32 align(1), //   @76
    gpe0_blk: u32 align(1), //     @80
    gpe1_blk: u32 align(1), //     @84
    pm1_evt_len: u8, //            @88
    pm1_cnt_len: u8, //            @89
    pm2_cnt_len: u8, //            @90
    pm_tmr_len: u8, //             @91
    gpe0_blk_len: u8, //           @92
    gpe1_blk_len: u8, //           @93
    gpe1_base: u8, //              @94
    cst_cnt: u8, //                @95
    p_lvl2_lat: u16 align(1), //   @96
    p_lvl3_lat: u16 align(1), //   @98
    flush_size: u16 align(1), //   @100
    flush_stride: u16 align(1), // @102
    duty_offset: u8, //            @104
    duty_width: u8, //             @105
    day_alrm: u8, //               @106
    mon_alrm: u8, //               @107
    century: u8, //                @108
    iapc_boot_arch: IapcBootArch align(1), //@109
    reserved2: u8, //              @111
    flags: u32 align(1), //        @112
    reset_reg: Gas, //             @116
    reset_value: u8, //            @128
    arm_boot_arch: u16 align(1), //@129
    fadt_minor_version: u8, //     @131  0 → FADT 6.0
    x_firmware_ctrl: u64 align(1), //@132
    x_dsdt: u64 align(1), //       @140
    x_pm1a_evt_blk: Gas, //        @148
    x_pm1b_evt_blk: Gas, //        @160
    x_pm1a_cnt_blk: Gas, //        @172
    x_pm1b_cnt_blk: Gas, //        @184
    x_pm2_cnt_blk: Gas, //         @196
    x_pm_tmr_blk: Gas, //          @208
    x_gpe0_blk: Gas, //            @220
    x_gpe1_blk: Gas, //            @232
    sleep_control_reg: Gas, //     @244
    sleep_status_reg: Gas, //      @256
    hypervisor_vendor_id: u64 align(1), //@268

    comptime {
        std.debug.assert(@sizeOf(Fadt) == 276); // ACPI 6.0: 276-byte FADT
    }
};

/// Build the standard ACPI SDT header value. Leaves the checksum byte zero for the
/// caller to patch once the body is laid down; `length` is the table's full length.
fn initHeader(oem: Oem, sig: *const [4]u8, length: u32, revision: u8) SdtHeader {
    return .{
        .signature = sig.*,
        .length = length,
        .revision = revision,
        .checksum = 0,
        .oem_id = oem.id,
        .oem_table_id = oem.table_id,
        .oem_revision = oem.revision,
        .creator_id = oem.creator_id,
        .creator_revision = oem.creator_revision,
    };
}

/// Write the standard ACPI SDT header at the start of a byte-buffer table.
fn sdtHeader(buf: []u8, oem: Oem, sig: *const [4]u8, length: u32, revision: u8) void {
    const h = initHeader(oem, sig, length, revision);
    @memcpy(buf[0..SDT_HDR], std.mem.asBytes(&h));
}

/// Place a generic SDT — a standard header wrapping `body` — at `gpa` in `ram`, and
/// patch its checksum. Returns the table's total length. Used for every SDT whose
/// payload is a plain byte body (RSDT, DSDT, MADT); the FADT and RSDP have fixed
/// struct layouts and are written directly.
fn writeTable(ram: []u8, gpa: Gpa, oem: Oem, sig: *const [4]u8, revision: u8, body: []const u8) usize {
    const len = SDT_HDR + body.len;
    const buf = ram[@intCast(gpa)..][0..len];
    sdtHeader(buf, oem, sig, @intCast(len), revision);
    @memcpy(buf[SDT_HDR..], body);
    buf[@offsetOf(SdtHeader, "checksum")] = checksum(buf);
    return len;
}

/// The byte that makes `bytes` sum to 0 mod 256 (the ACPI table checksum).
fn checksum(bytes: []const u8) u8 {
    var sum: u8 = 0;
    for (bytes) |b| sum +%= b;
    return 0 -% sum;
}

// ---- tests ----------------------------------------------------------------

const testing = std.testing;

const RSDP_GPA: Gpa = 0xF_0000;
const TEST_OEM = Oem{ .id = "TESTVM".*, .table_id = "TESTVMTB".*, .creator_id = "TEST".* };
const TABLES_GPA: Gpa = tablesGpa(RSDP_GPA);

// A representative machine description for the tests below.
const TEST_MADT = Madt{
    .lapic_addr = 0xFEE0_0000,
    .pcat_compat = true,
    .entries = &.{
        .{ .local_apic = .{ .uid = 0, .apic_id = 0 } },
        .{ .io_apic = .{ .id = 2, .addr = 0xFEC0_0000 } },
        .{ .local_apic_nmi = .{ .uid = 0xFF, .flags = .{ .polarity = .active_high, .trigger = .edge }, .lint = 1 } },
    },
};
const TEST_DSDT = Dsdt{
    .devices = &.{
        .{ .name = "VR00".*, .hid = "LNRO0005", .uid = 0, .mmio_base = 0xD000_0000, .mmio_size = 0x1000, .irq = 5 },
    },
    .s5 = .{ .a = 7, .b = 7 },
};

// The known-good, hand-encoded DSDT AML for TEST_DSDT — the golden oracle the AML
// encoder must reproduce byte-for-byte. Any drift here is an AML regression.
const GOLDEN_DSDT_AML = [_]u8{
    0x10, 0x43, 0x04, 0x5C, 0x5F, 0x53, 0x42, 0x5F, // Scope(\_SB), PkgLen 67
    0x5B, 0x82, 0x3A, 0x56, 0x52, 0x30, 0x30, //       Device(VR00), PkgLen 58
    0x08, 0x5F, 0x48, 0x49, 0x44, 0x0D, 0x4C, 0x4E, 0x52, 0x4F, 0x30, 0x30, 0x30, 0x35, 0x00, // Name(_HID,"LNRO0005")
    0x08, 0x5F, 0x55, 0x49, 0x44, 0x00, //             Name(_UID, 0)
    0x08, 0x5F, 0x43, 0x52, 0x53, 0x11, 0x1A, 0x0A, 0x17, // Name(_CRS, Buffer[23])
    0x86, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0xD0, 0x00, 0x10, 0x00, 0x00, // Memory32Fixed
    0x89, 0x06, 0x00, 0x03, 0x01, 0x05, 0x00, 0x00, 0x00, //                  Extended Interrupt
    0x79, 0x00, //                                     End tag
    0x08, 0x5F, 0x53, 0x35, 0x5F, 0x12, 0x08, 0x04, 0x0A, 0x07, 0x0A, 0x07, 0x00, 0x00, // Name(\_S5, Package{7,7,0,0})
};

fn buildInto(ram: []u8) !Gpa {
    return build(ram, .{ .rsdp_gpa = RSDP_GPA, .oem = TEST_OEM, .madt = TEST_MADT, .dsdt = TEST_DSDT });
}

fn sums0(bytes: []const u8) bool {
    var sum: u8 = 0;
    for (bytes) |b| sum +%= b;
    return sum == 0;
}

// Layout, recomputed independently of build().
const DSDT_LEN: Gpa = SDT_HDR + GOLDEN_DSDT_AML.len;
const FADT_GPA: Gpa = TABLES_GPA + RSDT_LEN;
const DSDT_GPA: Gpa = FADT_GPA + FADT_LEN;
const MADT_GPA: Gpa = DSDT_GPA + DSDT_LEN;

test "acpi: the AML encoder reproduces the golden DSDT byte-for-byte" {
    var scratch: [DSDT_AML_MAX]u8 = undefined;
    var b = Buf{ .data = &scratch };
    try encodeDsdt(&b, TEST_DSDT);
    try testing.expectEqualSlices(u8, &GOLDEN_DSDT_AML, b.used());
}

test "acpi: the AML encoder threads the device window/irq into _CRS" {
    var scratch: [DSDT_AML_MAX]u8 = undefined;
    var b = Buf{ .data = &scratch };
    try encodeDsdt(&b, .{ .devices = &.{
        .{ .name = "VR00".*, .hid = "LNRO0005", .mmio_base = 0xABCD_0000, .mmio_size = 0x2000, .irq = 9 },
    }, .s5 = .{ .a = 7, .b = 7 } });
    const aml = b.used();
    try testing.expect(std.mem.indexOf(u8, aml, "LNRO0005") != null);
    // Memory32Fixed base/size and the interrupt number reached the buffer, LE.
    try testing.expect(std.mem.indexOf(u8, aml, &[_]u8{ 0x00, 0x00, 0xCD, 0xAB }) != null); // base
    try testing.expect(std.mem.indexOf(u8, aml, &[_]u8{ 0x00, 0x20, 0x00, 0x00 }) != null); // size
    try testing.expect(std.mem.indexOf(u8, aml, &[_]u8{ 0x09, 0x00, 0x00, 0x00 }) != null); // irq
}

test "acpi: the AML encoder emits the generation ID devices byte-for-byte" {
    var scratch: [DSDT_AML_MAX]u8 = undefined;
    var b = Buf{ .data = &scratch };
    try encodeGenerationId(&b, .{ .addr = 0x0000_0001_000E_F000, .event_irq = 16 });
    const golden = [_]u8{
        0x5B, 0x82, 0x28, 0x56, 0x47, 0x45, 0x4E, // Device(VGEN), PkgLen 40
        0x08, 0x5F, 0x48, 0x49, 0x44, 0x0D, 0x56, 0x4D, 0x47, 0x45, 0x4E, 0x43, 0x54, 0x52, 0x00, // Name(_HID,"VMGENCTR")
        0x08, 0x5F, 0x55, 0x49, 0x44, 0x00, //             Name(_UID, 0)
        0x08, 0x41, 0x44, 0x44, 0x52, 0x12, 0x08, 0x02, // Name(ADDR, Package(2)
        0x0C, 0x00, 0xF0, 0x0E, 0x00, 0x01, //             { 0xEF000, 1 })
        0x5B, 0x82, 0x43, 0x04, 0x47, 0x45, 0x44, 0x30, // Device(GED0), PkgLen 67
        0x08, 0x5F, 0x48, 0x49, 0x44, 0x0D, 0x41, 0x43, 0x50, 0x49, 0x30, 0x30, 0x31, 0x33, 0x00, // Name(_HID,"ACPI0013")
        0x08, 0x5F, 0x55, 0x49, 0x44, 0x00, //             Name(_UID, 0)
        0x08, 0x5F, 0x43, 0x52, 0x53, 0x11, 0x0E, 0x0A, 0x0B, // Name(_CRS, Buffer[11])
        0x89, 0x06, 0x00, 0x03, 0x01, 0x10, 0x00, 0x00, 0x00, // Extended Interrupt(16)
        0x79, 0x00, //                                     End tag
        0x14, 0x13, 0x5F, 0x45, 0x56, 0x54, 0x01, //       Method(_EVT, 1)
        0x86, 0x5C, 0x2E, 0x5F, 0x53, 0x42, 0x5F, 0x56, 0x47, 0x45, 0x4E, 0x0A, 0x80, // Notify(\_SB.VGEN, 0x80)
    };
    try testing.expectEqualSlices(u8, &golden, b.used());
}

test "acpi: the generation ID devices sit inside the \\_SB scope after the declared devices" {
    var with: [DSDT_AML_MAX]u8 = undefined;
    var w = Buf{ .data = &with };
    try encodeDsdt(&w, .{ .devices = TEST_DSDT.devices, .s5 = TEST_DSDT.s5, .generation_id = .{ .addr = 0xEF000, .event_irq = 16 } });
    const aml = w.used();
    const vgen = std.mem.indexOf(u8, aml, "VGEN").?;
    try testing.expect(std.mem.indexOf(u8, aml, "VR00").? < vgen);
    try testing.expect(vgen < std.mem.indexOf(u8, aml, "GED0").?);
    try testing.expect(std.mem.indexOf(u8, aml, "GED0").? < std.mem.indexOf(u8, aml, "_S5_").?);
}

test "acpi: the MADT body encodes lapic addr, PCAT flag, and the three structures" {
    var scratch: [MADT_BODY_MAX]u8 = undefined;
    var b = Buf{ .data = &scratch };
    try encodeMadt(&b, TEST_MADT);
    const m = b.used();
    try testing.expectEqual(@as(usize, 8 + 8 + 12 + 6), m.len);
    try testing.expectEqual(@as(u32, 0xFEE0_0000), std.mem.readInt(u32, m[0..4], .little));
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, m[4..8], .little)); // PCAT_COMPAT
    // type 0 LAPIC (8) at 8, type 1 I/O APIC (12) at 16, type 4 NMI (6) at 28.
    try testing.expectEqual(@as(u8, 0), m[8]);
    try testing.expectEqual(@as(u8, 1), m[16]);
    try testing.expectEqual(@as(u8, 2), m[18]); // io apic id
    try testing.expectEqual(@as(u32, 0xFEC0_0000), std.mem.readInt(u32, m[20..24], .little));
    try testing.expectEqual(@as(u8, 4), m[28]);
    // MPS INTI flags (u16 at offset 31): active-high + edge still serializes to 0x0005.
    try testing.expectEqual(@as(u16, 0x0005), std.mem.readInt(u16, m[31..33], .little));
    try testing.expectEqual(@as(u8, 1), m[33]); // LINT#1
}

// The _CRS resource-descriptor flag bytes encode the same wiring as the MADT's
// MpsIntiFlags with different bit positions and an inverted polarity sense:
// MpsIntiFlags names the active-high case, ExtIntFlags names active-low. This
// pins both encodings so the two cannot drift into each other.
test "acpi: _CRS descriptor flags encode independently of the MADT's MpsIntiFlags" {
    try testing.expectEqual(@as(u8, 0x00), (Memory32Flags{}).toBits()); // read-only
    try testing.expectEqual(@as(u8, 0x01), (Memory32Flags{ .write_ok = true }).toBits());

    try testing.expectEqual(@as(u8, 1 << 0), (ExtIntFlags{ .consumer = true }).toBits());
    try testing.expectEqual(@as(u8, 1 << 1), (ExtIntFlags{ .edge = true }).toBits());
    try testing.expectEqual(@as(u8, 1 << 2), (ExtIntFlags{ .active_low = true }).toBits());
    try testing.expectEqual(@as(u8, 1 << 3), (ExtIntFlags{ .shared = true }).toBits());
    try testing.expectEqual(@as(u8, 1 << 4), (ExtIntFlags{ .wake_capable = true }).toBits());
    // What the virtio device node emits: consumer + edge, active-high, exclusive.
    try testing.expectEqual(@as(u8, 0x03), (ExtIntFlags{ .consumer = true, .edge = true }).toBits());

    // Same wiring, two encodings — the byte values differ, which is the trap.
    const crs_edge_high = (ExtIntFlags{ .consumer = true, .edge = true }).toBits(); // 0x03
    const madt_edge_high = (MpsIntiFlags{ .polarity = .active_high, .trigger = .edge }).toBits(); // 0x05
    try testing.expect(crs_edge_high != madt_edge_high);
}

test "acpi: MpsIntiFlags packs polarity and trigger into the low nibble" {
    try testing.expectEqual(@as(u16, 0x0000), (MpsIntiFlags{}).toBits()); // both conform
    try testing.expectEqual(@as(u16, 0x0001), (MpsIntiFlags{ .polarity = .active_high }).toBits());
    try testing.expectEqual(@as(u16, 0x0003), (MpsIntiFlags{ .polarity = .active_low }).toBits());
    try testing.expectEqual(@as(u16, 0x0004), (MpsIntiFlags{ .trigger = .edge }).toBits());
    try testing.expectEqual(@as(u16, 0x000C), (MpsIntiFlags{ .trigger = .level }).toBits());
    // The combination the MADT's LINT1=NMI entry uses.
    try testing.expectEqual(@as(u16, 0x0005), (MpsIntiFlags{ .polarity = .active_high, .trigger = .edge }).toBits());
}

test "acpi: the RSDP has 'RSD PTR ', revision 0, points at the RSDT, and checksums to 0" {
    const ram = try testing.allocator.alloc(u8, 0x10_0000);
    defer testing.allocator.free(ram);
    @memset(ram, 0);
    const rsdp = try buildInto(ram);
    try testing.expectEqual(RSDP_GPA, rsdp);

    const r = ram[RSDP_GPA..][0..RSDP_LEN];
    try testing.expectEqualStrings("RSD PTR ", r[0..8]);
    try testing.expectEqual(@as(u8, 0), r[15]); // revision 0
    try testing.expectEqual(@as(u32, TABLES_GPA), std.mem.readInt(u32, r[16..20], .little));
    try testing.expect(sums0(r)); // ACPI 1.0 checksum over the first 20 bytes
}

test "acpi: the RSDT lists the FADT then the MADT and checksums to 0" {
    const ram = try testing.allocator.alloc(u8, 0x10_0000);
    defer testing.allocator.free(ram);
    @memset(ram, 0);
    _ = try buildInto(ram);

    const t = ram[TABLES_GPA..][0..RSDT_LEN];
    try testing.expectEqualStrings("RSDT", t[0..4]);
    try testing.expectEqual(@as(u32, FADT_GPA), std.mem.readInt(u32, t[36..40], .little));
    try testing.expectEqual(@as(u32, MADT_GPA), std.mem.readInt(u32, t[40..44], .little));
    try testing.expect(sums0(t));
}

test "acpi: the FADT points at the DSDT (both DSDT and X_DSDT) and checksums to 0" {
    const ram = try testing.allocator.alloc(u8, 0x10_0000);
    defer testing.allocator.free(ram);
    @memset(ram, 0);
    _ = try buildInto(ram);

    const f = ram[FADT_GPA..][0..FADT_LEN];
    try testing.expectEqualStrings("FACP", f[0..4]);
    try testing.expectEqual(@as(u32, DSDT_GPA), std.mem.readInt(u32, f[40..44], .little)); // DSDT
    try testing.expectEqual(@as(u64, DSDT_GPA), std.mem.readInt(u64, f[140..148], .little)); // X_DSDT
    try testing.expect(sums0(f));

    const d = ram[DSDT_GPA..][0..DSDT_LEN];
    try testing.expectEqualStrings("DSDT", d[0..4]);
    try testing.expectEqualSlices(u8, &GOLDEN_DSDT_AML, d[SDT_HDR..]); // header wraps the golden AML
    try testing.expect(sums0(d));
}

test "acpi: the FADT carries the reset register (RESET_REG_SUP + GAS + value) when given" {
    const ram = try testing.allocator.alloc(u8, 0x10_0000);
    defer testing.allocator.free(ram);
    @memset(ram, 0);
    _ = try build(ram, .{
        .rsdp_gpa = RSDP_GPA,
        .oem = TEST_OEM,
        .reset_reg = 0xcf9,
        .reset_value = 0x06,
        .madt = TEST_MADT,
        .dsdt = TEST_DSDT,
    });
    const f = ram[FADT_GPA..][0..FADT_LEN];
    try testing.expectEqual(@as(u32, 1 << 10), std.mem.readInt(u32, f[112..116], .little)); // RESET_REG_SUP
    try testing.expectEqual(@as(u8, 1), f[116]); // GAS: SystemIO
    try testing.expectEqual(@as(u64, 0xcf9), std.mem.readInt(u64, f[120..128], .little)); // address
    try testing.expectEqual(@as(u8, 0x06), f[128]); // RESET_VALUE
    try testing.expect(sums0(f));

    // Default (no reset port) leaves the flag, GAS, and value zero.
    @memset(ram, 0);
    _ = try buildInto(ram);
    const f0 = ram[FADT_GPA..][0..FADT_LEN];
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, f0[112..116], .little));
    try testing.expectEqual(@as(u8, 0), f0[128]);
}

test "acpi: the FADT carries the PM1a event/control blocks and SCI_INT when given" {
    const ram = try testing.allocator.alloc(u8, 0x10_0000);
    defer testing.allocator.free(ram);
    @memset(ram, 0);
    _ = try build(ram, .{
        .rsdp_gpa = RSDP_GPA,
        .oem = TEST_OEM,
        .pm1a_evt_blk = 0x600,
        .pm1a_cnt_blk = 0x604,
        .pm1a_evt_len = 4,
        .pm1a_cnt_len = 2,
        .sci_int = 9,
        .madt = TEST_MADT,
        .dsdt = TEST_DSDT,
    });
    const f = ram[FADT_GPA..][0..FADT_LEN];
    try testing.expectEqual(@as(u16, 9), std.mem.readInt(u16, f[46..48], .little)); // SCI_INT
    try testing.expectEqual(@as(u32, 0x600), std.mem.readInt(u32, f[56..60], .little)); // PM1a_EVT_BLK
    try testing.expectEqual(@as(u32, 0x604), std.mem.readInt(u32, f[64..68], .little)); // PM1a_CNT_BLK
    try testing.expectEqual(@as(u8, 4), f[88]); // PM1_EVT_LEN
    try testing.expectEqual(@as(u8, 2), f[89]); // PM1_CNT_LEN
    try testing.expect(sums0(f));
}

test "acpi: rejects placement past the end of RAM" {
    const ram = try testing.allocator.alloc(u8, 0x1000);
    defer testing.allocator.free(ram);
    try testing.expectError(error.AcpiOutOfRange, build(ram, .{
        .rsdp_gpa = RSDP_GPA,
        .oem = TEST_OEM,
        .madt = TEST_MADT,
        .dsdt = TEST_DSDT,
    }));
}

// A device shaped like a read-only MMIO endpoint: no interrupt, ReadOnly window.
const RO_DEVICE = AmlDevice{ .name = "RE00".*, .hid = "VMMR0001", .uid = 1, .mmio_base = 0xD000_9000, .mmio_size = 0x2_0000, .memory_access = .read_only };

fn expectRefusedUnchanged(expected: BuildError, d: Dsdt, rsdp_gpa: Gpa) !void {
    const ram = try testing.allocator.alloc(u8, 0x10_0000);
    defer testing.allocator.free(ram);
    @memset(ram, 0xAA);
    try testing.expectError(expected, build(ram, .{ .rsdp_gpa = rsdp_gpa, .oem = TEST_OEM, .madt = TEST_MADT, .dsdt = d }));
    for (ram) |b| try testing.expectEqual(@as(u8, 0xAA), b);
}

test "acpi: an IRQ-less read-only device emits Memory32Fixed(ReadOnly) and no interrupt" {
    var scratch: [DSDT_AML_MAX]u8 = undefined;
    var b = Buf{ .data = &scratch };
    try encodeDsdt(&b, .{ .devices = &.{RO_DEVICE} });
    const crs = [_]u8{
        0x08, 0x5F, 0x43, 0x52, 0x53, 0x11, 0x11, 0x0A, 0x0E, // Name(_CRS, Buffer[14])
        0x86, 0x09, 0x00, 0x00, 0x00, 0x90, 0x00, 0xD0, 0x00, 0x00, 0x02, 0x00, // Memory32Fixed(ReadOnly)
        0x79, 0x00, //                                     End tag
    };
    const aml = b.used();
    try testing.expect(std.mem.endsWith(u8, aml, &crs));
    try testing.expect(std.mem.indexOfScalar(u8, aml, 0x89) == null); // no Extended Interrupt
}

test "acpi: an explicit IRQ 0 is an interrupt, not an absent one" {
    var scratch: [DSDT_AML_MAX]u8 = undefined;
    var b = Buf{ .data = &scratch };
    var dev = RO_DEVICE;
    dev.irq = 0;
    try encodeDsdt(&b, .{ .devices = &.{dev} });
    try testing.expect(std.mem.indexOf(u8, b.used(), &[_]u8{ 0x89, 0x06, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00 }) != null);
}

test "acpi: build refuses invalid devices before writing RAM" {
    const gen = GenerationId{ .addr = 0xEF000, .event_irq = 16 };
    var bad = RO_DEVICE;
    try expectRefusedUnchanged(error.InvalidAcpiDevice, .{ .devices = &.{ RO_DEVICE, RO_DEVICE } }, RSDP_GPA);
    bad.name = "VGEN".*;
    try expectRefusedUnchanged(error.InvalidAcpiDevice, .{ .devices = &.{bad}, .generation_id = gen }, RSDP_GPA);
    bad.name = "GED0".*;
    try expectRefusedUnchanged(error.InvalidAcpiDevice, .{ .devices = &.{bad}, .generation_id = gen }, RSDP_GPA);
    bad.name = "0BAD".*;
    try expectRefusedUnchanged(error.InvalidAcpiDevice, .{ .devices = &.{bad} }, RSDP_GPA);
    bad.name = "Re00".*;
    try expectRefusedUnchanged(error.InvalidAcpiDevice, .{ .devices = &.{bad} }, RSDP_GPA);
    bad = RO_DEVICE;
    bad.hid = "";
    try expectRefusedUnchanged(error.InvalidAcpiDevice, .{ .devices = &.{bad} }, RSDP_GPA);
    bad.hid = "VMM R001";
    try expectRefusedUnchanged(error.InvalidAcpiDevice, .{ .devices = &.{bad} }, RSDP_GPA);
    bad = RO_DEVICE;
    bad.mmio_size = 0;
    try expectRefusedUnchanged(error.InvalidAcpiDevice, .{ .devices = &.{bad} }, RSDP_GPA);
    bad = RO_DEVICE;
    bad.mmio_base = 0xFFFF_F000;
    bad.mmio_size = 0x2000;
    try expectRefusedUnchanged(error.InvalidAcpiDevice, .{ .devices = &.{bad} }, RSDP_GPA);
    bad = RO_DEVICE;
    bad.memory_access = @enumFromInt(2);
    try expectRefusedUnchanged(error.InvalidAcpiDevice, .{ .devices = &.{bad} }, RSDP_GPA);
}

test "acpi: VGEN and GED0 are ordinary names without a generation ID" {
    var named = RO_DEVICE;
    named.name = "VGEN".*;
    var scratch: [DSDT_AML_MAX]u8 = undefined;
    var b = Buf{ .data = &scratch };
    try validateDsdt(.{ .devices = &.{named} });
    try encodeDsdt(&b, .{ .devices = &.{named} });
}

test "acpi: a window ending exactly at 4 GiB is representable" {
    var top = RO_DEVICE;
    top.mmio_base = 0xFFFF_F000;
    top.mmio_size = 0x1000;
    try validateDsdt(.{ .devices = &.{top} });
}

test "acpi: build refuses an oversized description with AcpiTooLarge before writing RAM" {
    const long_hid: [300]u8 = @splat('A');
    var big = RO_DEVICE;
    big.hid = &long_hid;
    try expectRefusedUnchanged(error.AcpiTooLarge, .{ .devices = &.{big} }, RSDP_GPA);
}

test "acpi: build refuses table addresses that overflow" {
    try expectRefusedUnchanged(error.AcpiOutOfRange, TEST_DSDT, std.math.maxInt(Gpa) - 4);
}

test "acpi: nine virtio nodes, eight endpoints and the generation ID fit the DSDT budget" {
    var devices: [17]AmlDevice = undefined;
    for (devices[0..9], 0..) |*d, i| d.* = .{
        .name = .{ 'V', 'R', '0', '0' + @as(u8, @intCast(i)) },
        .hid = "LNRO0005",
        .mmio_base = 0xD000_0000 + @as(u32, @intCast(i)) * 0x1000,
        .mmio_size = 0x1000,
        .irq = 5 + @as(u32, @intCast(i)),
    };
    for (devices[9..], 0..) |*d, i| d.* = .{
        .name = .{ 'R', 'E', '0', '0' + @as(u8, @intCast(i)) },
        .hid = "VMMR0001",
        .uid = std.math.maxInt(u32) - @as(u32, @intCast(i)),
        .mmio_base = 0xD000_9000 + @as(u32, @intCast(i)) * 0x2_0000,
        .mmio_size = 0x2_0000,
        .memory_access = .read_only,
    };
    const ram = try testing.allocator.alloc(u8, 0x10_0000);
    defer testing.allocator.free(ram);
    @memset(ram, 0);
    const rsdp = try build(ram, .{
        .rsdp_gpa = RSDP_GPA,
        .oem = TEST_OEM,
        .madt = TEST_MADT,
        .dsdt = .{ .devices = &devices, .s5 = .{ .a = 5, .b = 5 }, .generation_id = .{ .addr = 0xEF000, .event_irq = 16 } },
    });
    try testing.expectEqual(RSDP_GPA, rsdp);
    const dsdt = ram[@intCast(DSDT_GPA)..];
    const len = std.mem.readInt(u32, dsdt[4..8], .little);
    try testing.expect(len - SDT_HDR <= DSDT_AML_MAX);
    try testing.expect(sums0(dsdt[0..len]));
}
