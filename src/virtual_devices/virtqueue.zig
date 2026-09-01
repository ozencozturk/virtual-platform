//! Split virtqueue mechanics: the descriptor table, the available ring a driver
//! posts buffers to, and the used ring a device answers in.
//!
//! A device supplies what the buffers mean; this supplies the walking and the
//! bookkeeping.

const std = @import("std");
const bits = @import("bits");

/// Descriptor table entry size: addr, len, flags, next.
pub const DESC_BYTES = 16;

/// Descriptor flags.
pub const DescFlags = packed struct(u16) {
    /// Another descriptor follows in this chain.
    next: bool = false,
    /// Device-writable; clear means driver-readable.
    write: bool = false,
    indirect: bool = false,
    _rsvd: u13 = 0,
};

/// One descriptor table entry.
pub const Descriptor = struct {
    addr: u64 = 0,
    len: u32 = 0,
    flags: DescFlags = .{},
    next: u16 = 0,
};

/// Receives valid guest-memory ranges resolved through `Guest`. The callback
/// observes ranges rather than access direction because reads and writes both
/// resolve through `Guest.slice`.
pub const AccessTracker = struct {
    context: *anyopaque,
    mark: *const fn (context: *anyopaque, offset: u64, len: u64) void,
};

/// Guest RAM and the physical address it starts at.
///
/// Every access is bounds-checked and answers null rather than trapping, so a
/// driver that programs an address outside RAM cannot fault the host.
pub const Guest = struct {
    memory: []u8,
    base: u64,
    access_tracker: ?AccessTracker = null,

    /// `len` bytes at guest physical `addr`, or null when out of range.
    pub fn slice(self: Guest, addr: u64, len: u64) ?[]u8 {
        if (addr < self.base) return null;
        const off = addr - self.base;
        if (!bits.inBounds(off, len, self.memory.len)) return null;
        if (self.access_tracker) |tracker| tracker.mark(tracker.context, off, len);
        return self.memory[@intCast(off)..][0..@intCast(len)];
    }

    /// Little-endian integer at `addr`, or null when out of range.
    pub fn read(self: Guest, comptime T: type, addr: u64) ?T {
        const s = self.slice(addr, @sizeOf(T)) orelse return null;
        return std.mem.readInt(T, s[0..@sizeOf(T)], .little);
    }

    /// Store a little-endian integer at `addr`; an out-of-range write is dropped.
    pub fn write(self: Guest, comptime T: type, addr: u64, v: T) void {
        const s = self.slice(addr, @sizeOf(T)) orelse return;
        std.mem.writeInt(T, s[0..@sizeOf(T)], v, .little);
    }
};

/// One queue: the layout its driver programmed, and how far the device has got.
pub const Queue = struct {
    /// Ring depth the driver asked for.
    num: u32 = 0,
    ready: u32 = 0,
    desc: u64 = 0,
    avail: u64 = 0,
    used: u64 = 0,
    /// Next available-ring slot to consume. Wraps with the ring, not with `idx`.
    last_avail: u16 = 0,
    used_idx: u16 = 0,

    /// Whether the driver has finished programming this queue.
    pub fn live(self: Queue) bool {
        return self.ready == 1 and self.num != 0;
    }

    /// Head descriptor of the next posted chain, or null when none is posted.
    pub fn nextHead(self: Queue, g: Guest) ?u16 {
        const idx = g.read(u16, self.avail + 2) orelse return null;
        if (idx == self.last_avail) return null;
        const slot = self.last_avail % @as(u16, @intCast(self.num));
        return g.read(u16, self.avail + 4 + @as(u64, slot) * 2);
    }

    /// Walk the descriptor chain starting at `head`.
    pub fn chain(self: Queue, g: Guest, head: u16) Chain {
        return .{ .q = self, .g = g, .idx = head };
    }

    /// Step past a chain in the available ring and record it in the used ring
    /// with the bytes the device wrote. Both halves together: either alone
    /// loses the chain or serves it twice.
    pub fn complete(self: *Queue, g: Guest, head: u16, len: u32) void {
        self.last_avail +%= 1;
        const slot = self.used_idx % @as(u16, @intCast(self.num));
        const entry = self.used + 4 + @as(u64, slot) * 8;
        g.write(u32, entry, head);
        g.write(u32, entry + 4, len);
        self.used_idx +%= 1;
        g.write(u16, self.used + 2, self.used_idx);
    }
};

/// Iterates one descriptor chain. Ends at the last descriptor, at an index
/// outside the ring, at an unreadable entry, or after as many descriptors as the
/// ring is deep, so a chain looped back on itself cannot spin.
pub const Chain = struct {
    q: Queue,
    g: Guest,
    idx: u16,
    hops: u32 = 0,
    done: bool = false,

    /// The next descriptor, or null at the end of the chain.
    pub fn next(self: *Chain) ?Descriptor {
        if (self.done or self.hops >= self.q.num or self.idx >= self.q.num) return null;
        self.hops += 1;
        const at = self.q.desc + @as(u64, self.idx) * DESC_BYTES;
        const d: Descriptor = .{
            .addr = self.g.read(u64, at) orelse return null,
            .len = self.g.read(u32, at + 8) orelse return null,
            .flags = @bitCast(self.g.read(u16, at + 12) orelse return null),
            .next = self.g.read(u16, at + 14) orelse return null,
        };
        if (d.flags.next) self.idx = d.next else self.done = true;
        return d;
    }
};

// ---- tests ----------------------------------------------------------------

const testing = std.testing;
const BASE: u64 = 0x8000_0000;
const DESC_AT: u64 = BASE + 0x1000;
const AVAIL_AT: u64 = BASE + 0x2000;
const USED_AT: u64 = BASE + 0x3000;

/// A queue whose rings sit at the fixed test addresses.
fn testQueue(num: u32) Queue {
    return .{ .num = num, .ready = 1, .desc = DESC_AT, .avail = AVAIL_AT, .used = USED_AT };
}

/// Write descriptor `i` of the test descriptor table.
fn putDesc(g: Guest, i: u16, addr: u64, len: u32, flags: DescFlags, nxt: u16) void {
    const at = DESC_AT + @as(u64, i) * DESC_BYTES;
    g.write(u64, at, addr);
    g.write(u32, at + 8, len);
    g.write(u16, at + 12, @bitCast(flags));
    g.write(u16, at + 14, nxt);
}

/// Post chain head `head` in available-ring slot `slot` and publish it.
fn postAvail(g: Guest, slot: u16, head: u16, idx: u16) void {
    g.write(u16, AVAIL_AT + 4 + @as(u64, slot) * 2, head);
    g.write(u16, AVAIL_AT + 2, idx);
}

test "guest: an access inside RAM resolves and one outside answers null" {
    var ram: [0x100]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = BASE };
    g.write(u32, BASE + 0x10, 0xdead_beef);
    try testing.expectEqual(@as(?u32, 0xdead_beef), g.read(u32, BASE + 0x10));
    try testing.expectEqual(@as(?u32, null), g.read(u32, BASE - 4));
    try testing.expectEqual(@as(?u32, null), g.read(u32, BASE + 0x100));
    try testing.expectEqual(@as(?[]u8, null), g.slice(BASE + 0xfe, 4));
}

test "guest: a write outside RAM is dropped rather than trapping" {
    var ram: [0x10]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = BASE };
    g.write(u32, BASE + 0x40, 0xffff_ffff);
    try testing.expectEqual(@as(u8, 0), ram[0]);
}

test "guest: an access tracker conservatively sees every resolved slice" {
    const Seen = struct {
        offset: u64 = 0,
        len: u64 = 0,
        calls: u32 = 0,

        fn mark(context: *anyopaque, offset: u64, len: u64) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.offset = offset;
            self.len = len;
            self.calls += 1;
        }
    };

    var ram: [0x100]u8 = @splat(0);
    var seen = Seen{};
    const g = Guest{
        .memory = &ram,
        .base = BASE,
        .access_tracker = .{ .context = &seen, .mark = Seen.mark },
    };
    _ = g.read(u32, BASE + 0x20);
    try testing.expectEqual(@as(u64, 0x20), seen.offset);
    try testing.expectEqual(@as(u64, 4), seen.len);
    try testing.expectEqual(@as(u32, 1), seen.calls);

    try testing.expectEqual(@as(?[]u8, null), g.slice(BASE + ram.len, 1));
    try testing.expectEqual(@as(u32, 1), seen.calls);
}

test "queue: live only once the driver has set both ready and a depth" {
    try testing.expect(!(Queue{}).live());
    try testing.expect(!(Queue{ .ready = 1 }).live());
    try testing.expect(!(Queue{ .num = 4 }).live());
    try testing.expect((Queue{ .ready = 1, .num = 4 }).live());
}

test "queue: nextHead answers the posted chain and null once it is consumed" {
    var ram: [0x4000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = BASE };
    var q = testQueue(4);

    try testing.expectEqual(@as(?u16, null), q.nextHead(g));
    postAvail(g, 0, 3, 1);
    try testing.expectEqual(@as(?u16, 3), q.nextHead(g));

    q.complete(g, 3, 0);
    try testing.expectEqual(@as(?u16, null), q.nextHead(g));
}

test "queue: the available ring wraps at the negotiated depth" {
    var ram: [0x4000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = BASE };
    var q = testQueue(2);

    // Slot is index modulo depth, so the third posting reuses slot 0.
    postAvail(g, 0, 7, 3);
    q.last_avail = 2;
    try testing.expectEqual(@as(?u16, 7), q.nextHead(g));
}

test "queue: complete records the head and length and publishes the used index" {
    var ram: [0x4000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = BASE };
    var q = testQueue(4);

    q.complete(g, 2, 512);
    try testing.expectEqual(@as(?u32, 2), g.read(u32, USED_AT + 4));
    try testing.expectEqual(@as(?u32, 512), g.read(u32, USED_AT + 8));
    try testing.expectEqual(@as(?u16, 1), g.read(u16, USED_AT + 2));
    try testing.expectEqual(@as(u16, 1), q.last_avail);
}

test "queue: the used ring wraps at the negotiated depth" {
    var ram: [0x4000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = BASE };
    var q = testQueue(2);

    q.complete(g, 0, 1);
    q.complete(g, 1, 2);
    q.complete(g, 5, 3); // slot 0 again
    try testing.expectEqual(@as(?u32, 5), g.read(u32, USED_AT + 4));
    try testing.expectEqual(@as(?u16, 3), g.read(u16, USED_AT + 2));
}

test "chain: walks descriptors in order and stops when next is clear" {
    var ram: [0x4000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = BASE };
    const q = testQueue(4);

    putDesc(g, 0, BASE + 0x10, 16, .{ .next = true }, 1);
    putDesc(g, 1, BASE + 0x20, 32, .{ .next = true, .write = true }, 2);
    putDesc(g, 2, BASE + 0x30, 1, .{ .write = true }, 0);

    var c = q.chain(g, 0);
    const a = c.next().?;
    try testing.expectEqual(@as(u64, BASE + 0x10), a.addr);
    try testing.expect(!a.flags.write);
    const b = c.next().?;
    try testing.expectEqual(@as(u32, 32), b.len);
    try testing.expect(b.flags.write);
    try testing.expectEqual(@as(u32, 1), c.next().?.len);
    try testing.expectEqual(@as(?Descriptor, null), c.next());
}

test "chain: a descriptor index outside the ring ends the walk" {
    var ram: [0x4000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = BASE };
    const q = testQueue(2);

    putDesc(g, 0, BASE + 0x10, 4, .{ .next = true }, 9); // 9 >= num
    var c = q.chain(g, 0);
    try testing.expect(c.next() != null);
    try testing.expectEqual(@as(?Descriptor, null), c.next());
}

test "chain: a chain that points back at itself ends rather than spinning" {
    var ram: [0x4000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = BASE };
    const q = testQueue(4);

    putDesc(g, 0, BASE + 0x10, 4, .{ .next = true }, 1);
    putDesc(g, 1, BASE + 0x20, 4, .{ .next = true }, 0);

    var c = q.chain(g, 0);
    var seen: usize = 0;
    while (c.next() != null) seen += 1;
    try testing.expectEqual(@as(usize, q.num), seen);
}

test "chain: a head outside the ring yields nothing" {
    var ram: [0x4000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = BASE };
    const q = testQueue(4);

    var c = q.chain(g, 4);
    try testing.expectEqual(@as(?Descriptor, null), c.next());
}

test "chain: a descriptor table outside RAM yields nothing" {
    var ram: [0x100]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = BASE };
    var q = testQueue(4);
    q.desc = BASE + 0x1_0000;

    var c = q.chain(g, 0);
    try testing.expectEqual(@as(?Descriptor, null), c.next());
}
