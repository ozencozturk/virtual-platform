//! The x86 Linux boot protocol: the bzImage setup header and the 4 KiB
//! boot_params zero page (Documentation/arch/x86/boot.rst). `placement` copies
//! an image and its initramfs into guest RAM at addresses the caller gives.

pub const bzimage = @import("bzimage.zig");
pub const boot_params = @import("boot_params.zig");
pub const placement = @import("placement.zig");

test {
    _ = @import("bzimage.zig");
    _ = @import("boot_params.zig");
    _ = @import("placement.zig");
}
