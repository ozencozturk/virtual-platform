//! How each architecture expects Linux to be entered: the image header formats
//! and boot-protocol structures. Copying payloads into guest RAM lives here
//! too; the addresses do not. Where a kernel, initrd or DTB goes belongs to a
//! machine rather than to the protocol, and is passed in.

pub const arm64 = @import("arm64.zig");
pub const x86 = @import("x86/x86.zig");

test {
    _ = @import("arm64.zig");
    _ = @import("x86/x86.zig");
}
