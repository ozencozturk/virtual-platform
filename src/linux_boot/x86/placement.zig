const std = @import("std");
const bzimage = @import("bzimage.zig");

// Places a bzImage and its initramfs in guest RAM: strips the real-mode setup,
// copies the protected-mode kernel, and copies the archive above it. Pure over
// the caller's `ram` slice with no I/O, like `boot_params`: guest RAM is mapped
// from GPA 0, so a guest-physical address is an offset into it. `init_size` and
// `ramdisk_image` are per Documentation/arch/x86/boot.rst.
//
// Addresses are the caller's. Placement is bounded below by the kernel's
// decompression footprint and above by the end of RAM. Both are checked.

/// Guest-physical address.
const Gpa = u64;

/// The conventional x86-64 load address, and the usual pref_address.
pub const KERNEL_LOAD_GPA: Gpa = 0x0100_0000; // 16 MiB
/// Entry point of a kernel placed at KERNEL_LOAD_GPA.
pub const KERNEL_ENTRY: Gpa = KERNEL_LOAD_GPA + bzimage.ENTRY64_OFFSET;

/// What was placed, and where.
pub const Loaded = struct {
    header: bzimage.SetupHeader, // the image's parsed header
    pm_len: usize, //               bytes of protected-mode kernel placed
    load_gpa: Gpa, //               where it went (entry = load_gpa + bzimage.ENTRY64_OFFSET)
    initrd_gpa: Gpa, //             where the initramfs went (0 if none)
    initrd_len: usize, //           its length in bytes (0 if none)
};

/// Where the payloads go. `initrd_gpa` has no default: it is a property of the
/// machine, not of the boot protocol.
pub const Layout = struct {
    kernel_gpa: Gpa = KERNEL_LOAD_GPA,
    initrd_gpa: Gpa,
};

/// Copy the protected-mode kernel to `at.kernel_gpa`, and `initrd` when given
/// to `at.initrd_gpa`. `initrd == null` places no archive.
pub fn place(ram: []u8, image: []const u8, initrd: ?[]const u8, at: Layout) !Loaded {
    if (at.initrd_gpa > 0xFFFF_FFFF) return error.InitrdUnaddressable; // ramdisk_image is a u32
    const k = try bzimage.parse(image);
    // The kernel needs `init_size` contiguous bytes from the load address (its
    // decompression scratch), which exceeds the file bytes — reserve the larger.
    const kfoot = @max(k.protected_mode.len, k.header.init_size);
    if (at.kernel_gpa + kfoot > ram.len) return error.PayloadTooLarge;
    // That footprint must not reach the initrd region, or decompression would
    // overwrite the ramdisk the kernel later mounts. Checked with no initrd
    // too: the region is reserved whether or not this boot fills it.
    if (at.kernel_gpa + kfoot > at.initrd_gpa) return error.KernelFootprintOverflow;
    @memcpy(ram[at.kernel_gpa..][0..k.protected_mode.len], k.protected_mode);

    var placed_gpa: Gpa = 0;
    var initrd_len: usize = 0;
    if (initrd) |data| {
        if (at.initrd_gpa + data.len > ram.len) return error.InitrdOverflow;
        @memcpy(ram[at.initrd_gpa..][0..data.len], data);
        placed_gpa = at.initrd_gpa;
        initrd_len = data.len;
    }
    return .{
        .header = k.header,
        .pm_len = k.protected_mode.len,
        .load_gpa = at.kernel_gpa,
        .initrd_gpa = placed_gpa,
        .initrd_len = initrd_len,
    };
}

// ---- tests ----------------------------------------------------------------

const testing = std.testing;

// An initrd address with room for a kernel below it.
const INITRD_AT: Gpa = 0x0300_0000;
// Guest RAM large enough to back INITRD_AT and an archive above it.
const RAM_BYTES = 512 * 1024 * 1024;

// Fabricate a minimal valid bzImage into `buf`: header at 0x1f1 for `setup_sects`
// and `init_size`, plus a recognizable pattern in the protected-mode part.
// Returns the real-mode size (where the PM kernel begins).
fn fakeBzImage(buf: []u8, setup_sects: u8, init_size: u32) usize {
    @memset(buf, 0);
    buf[bzimage.SetupHeader.OFFSET] = setup_sects;
    std.mem.writeInt(u16, buf[0x1fe..][0..2], bzimage.BOOT_FLAG, .little);
    std.mem.writeInt(u32, buf[0x202..][0..4], bzimage.HDRS_MAGIC, .little);
    std.mem.writeInt(u16, buf[0x236..][0..2], bzimage.XLF_KERNEL_64, .little);
    std.mem.writeInt(u32, buf[0x260..][0..4], init_size, .little);
    const sects: usize = if (setup_sects == 0) 4 else setup_sects;
    const rm = (sects + 1) * 512;
    for (buf[rm..], 0..) |*b, i| b.* = @truncate(i +% 0xC0);
    return rm;
}

test "every decl compiles" {
    testing.refAllDecls(@This());
}

test "place: strips the setup and copies the PM kernel to the load address" {
    var img: [0x2000]u8 = undefined;
    const rm = fakeBzImage(&img, 1, 0x40); // small init_size so the buffer stays modest
    const pm_len = img.len - rm;

    const ram = try std.heap.page_allocator.alloc(u8, KERNEL_LOAD_GPA + pm_len);
    defer std.heap.page_allocator.free(ram);
    ram[KERNEL_LOAD_GPA - 1] = 0xAA; // sentinel just below the load point

    const loaded = try place(ram, &img, null, .{ .initrd_gpa = INITRD_AT });

    try testing.expectEqual(KERNEL_LOAD_GPA, loaded.load_gpa);
    try testing.expectEqual(pm_len, loaded.pm_len);
    try testing.expectEqual(@as(u8, 1), loaded.header.setup_sects);
    try testing.expectEqual(@as(u64, 0), loaded.initrd_gpa); // no ramdisk reported
    try testing.expectEqual(@as(usize, 0), loaded.initrd_len);
    // The PM bytes landed at the load address, exactly the stripped tail of the file.
    try testing.expectEqualSlices(u8, img[rm..], ram[KERNEL_LOAD_GPA..][0..pm_len]);
    try testing.expectEqual(@as(u8, 0xAA), ram[KERNEL_LOAD_GPA - 1]); // the prefix is untouched
}

test "place: copies the initramfs to its address and reports its extent" {
    var img: [0x2000]u8 = undefined;
    _ = fakeBzImage(&img, 1, 0x40);
    const ram = try std.heap.page_allocator.alloc(u8, RAM_BYTES);
    defer std.heap.page_allocator.free(ram);
    ram[INITRD_AT - 1] = 0xBB; // sentinel just below the initrd

    const initrd = "CPIO-INITRAMFS-BYTES"; // stand-in for the newc archive
    const loaded = try place(ram, &img, initrd, .{ .initrd_gpa = INITRD_AT });

    try testing.expectEqual(INITRD_AT, loaded.initrd_gpa);
    try testing.expectEqual(initrd.len, loaded.initrd_len);
    try testing.expectEqualStrings(initrd, ram[INITRD_AT..][0..initrd.len]);
    try testing.expectEqual(@as(u8, 0xBB), ram[INITRD_AT - 1]); // byte below is untouched
}

test "place: uses the kernel address it is given" {
    var img: [0x2000]u8 = undefined;
    const rm = fakeBzImage(&img, 1, 0x40);
    const at: Gpa = 0x0080_0000; // half the conventional pref_address
    const ram = try std.heap.page_allocator.alloc(u8, RAM_BYTES);
    defer std.heap.page_allocator.free(ram);

    const loaded = try place(ram, &img, null, .{ .kernel_gpa = at, .initrd_gpa = INITRD_AT });

    try testing.expectEqual(at, loaded.load_gpa);
    try testing.expectEqualSlices(u8, img[rm..], ram[at..][0 .. img.len - rm]);
}

test "place: errors when the kernel does not fit in RAM" {
    var img: [0x2000]u8 = undefined;
    _ = fakeBzImage(&img, 1, 0x40);
    var small: [0x1000]u8 = undefined; // far smaller than the load address
    try testing.expectError(error.PayloadTooLarge, place(&small, &img, null, .{ .initrd_gpa = INITRD_AT }));
}

test "place: honors init_size — reserves the kernel's full runtime footprint" {
    var img: [0x2000]u8 = undefined;
    _ = fakeBzImage(&img, 1, 0x0080_0000); // 8 MiB init_size, ≫ the file's PM bytes
    // Big enough for the PM bytes but not for init_size ⇒ must still refuse.
    const ram = try std.heap.page_allocator.alloc(u8, KERNEL_LOAD_GPA + 0x2000);
    defer std.heap.page_allocator.free(ram);
    try testing.expectError(error.PayloadTooLarge, place(ram, &img, null, .{ .initrd_gpa = INITRD_AT }));
}

test "place: refuses a kernel footprint that would reach the initrd region" {
    var img: [0x2000]u8 = undefined;
    // init_size chosen so the footprint lands just past the initrd address — the
    // decompression scratch would clobber the ramdisk, so placement must refuse
    // even though the RAM is large enough to hold it.
    _ = fakeBzImage(&img, 1, @intCast(INITRD_AT - KERNEL_LOAD_GPA + 0x1000));
    const ram = try std.heap.page_allocator.alloc(u8, RAM_BYTES);
    defer std.heap.page_allocator.free(ram);
    try testing.expectError(error.KernelFootprintOverflow, place(ram, &img, null, .{ .initrd_gpa = INITRD_AT }));
}

test "place: refuses an initrd address a u32 ramdisk_image cannot name" {
    var img: [0x2000]u8 = undefined;
    _ = fakeBzImage(&img, 1, 0x40);
    var small: [0x1000]u8 = undefined;
    try testing.expectError(error.InitrdUnaddressable, place(&small, &img, null, .{ .initrd_gpa = 0x1_0000_0000 }));
}

test "place: refuses an initrd that runs past the end of RAM" {
    var img: [0x2000]u8 = undefined;
    _ = fakeBzImage(&img, 1, 0x40);
    const ram = try std.heap.page_allocator.alloc(u8, INITRD_AT + 4);
    defer std.heap.page_allocator.free(ram);
    try testing.expectError(error.InitrdOverflow, place(ram, &img, "12345", .{ .initrd_gpa = INITRD_AT }));
}

test "place: propagates a parse error from a malformed image" {
    var img: [0x2000]u8 = @splat(0); // boot_flag = 0 ≠ 0xAA55
    var small: [0x1000]u8 = undefined;
    try testing.expectError(error.BadBootFlag, place(&small, &img, null, .{ .initrd_gpa = INITRD_AT }));
}
