//! virtio-vsock over the memory-mapped transport: packets between a guest and
//! whoever owns the device, addressed by context id and port rather than by an
//! address a network assigns.
//!
//! This model carries whole packets, header included. The stream protocol they
//! describe — connection setup, credit, shutdown — belongs to whoever is on the
//! other end.

const std = @import("std");
const mmio = @import("virtio_mmio.zig");
const virtqueue = @import("virtqueue.zig");
const packet_fifo = @import("packet_fifo.zig");

pub const Guest = virtqueue.Guest;

/// `struct virtio_vsock_config`.
const Config = extern struct {
    /// Which guest this is, as both ends address it.
    guest_cid: u64 = 3,
};

/// Queue indices fixed by the spec.
const RX_QUEUE = 0;
const TX_QUEUE = 1;
const EVENT_QUEUE = 2;
const NUM_QUEUES = 3;

/// Ring depth offered to the driver. Power of two, as the spec requires.
pub const QUEUE_SIZE: u32 = 64;

/// Whole packets retained in each direction.
const RX_PACKETS = 8;
const TX_PACKETS = 8;

/// The only event this device raises: the other end went away, and every
/// connection with it.
pub const EVENT_TRANSPORT_RESET: u32 = 0;

pub const VirtioVsock = struct {
    pub const MMIO_SIZE = mmio.MMIO_SIZE;

    /// Context id every guest reserves for the host it is running on.
    pub const HOST_CID: u64 = 2;

    /// `struct virtio_vsock_hdr`, in front of every packet in either direction.
    pub const PacketHeader = extern struct {
        src_cid: u64 = 0,
        dst_cid: u64 = 0,
        src_port: u32 = 0,
        dst_port: u32 = 0,
        len: u32 = 0,
        type: u16 = 0,
        op: u16 = 0,
        flags: u32 = 0,
        buf_alloc: u32 = 0,
        fwd_cnt: u32 = 0,

        pub const BYTES = 44;
    };

    /// Longest packet carried, header included.
    pub const MAX_PACKET = PacketHeader.BYTES + 4096;

    pub const FailureCause = enum {
        tx_oversized,
        tx_short_header,
        tx_short_payload,
        tx_bad_chain,
        queue_invalid,
        ring_alias,
        unexpected_enqueue_failure,
        progress_bound,
        counter_overflow,
    };

    pub const Failure = struct {
        cause: FailureCause,
        queue: ?u8 = null,
        head: ?u16 = null,
    };

    pub const Integrity = union(enum) { valid, invalid: Failure };

    pub const Diagnostics = struct {
        tx_rejected_oversize_packets: u64 = 0,
        tx_rejected_malformed_packets: u64 = 0,
        tx_rejected_known_payload_bytes: u64 = 0,
        tx_rejected_unknown_extent_packets: u64 = 0,
        rx_unusable_heads: u64 = 0,
        rx_enqueue_refused_packets: u64 = 0,
    };

    pub const Frontier = struct {
        active: bool = false,
        queue: virtqueue.Queue = .{},
        avail_idx: u16 = 0,
        heads: u16 = 0,
    };

    pub const ServiceVisit = struct {
        frontiers: [NUM_QUEUES]Frontier = @splat(.{}),
        tx_completions: u16 = 0,
        rx_completions: u16 = 0,
        event_completions: u16 = 0,
        entry_tx_packets: u16 = 0,
        metadata: [NUM_QUEUES * 3]Range = undefined,
        metadata_count: usize = 0,

        fn completions(self: *const ServiceVisit, queue: usize) u16 {
            return switch (queue) {
                RX_QUEUE => self.rx_completions,
                TX_QUEUE => self.tx_completions,
                else => self.event_completions,
            };
        }
    };

    const Transport = mmio.Transport(.{
        .device_id = 19,
        .num_queues = NUM_QUEUES,
        .queue_size = QUEUE_SIZE,
    });

    transport: Transport = .{},
    config: Config = .{},

    /// Packets waiting for the guest to post a buffer.
    rx: packet_fifo.Fifo(RX_PACKETS, MAX_PACKET) = .{},
    /// Packets the guest has sent, waiting for the owner to take them.
    tx: packet_fifo.Fifo(TX_PACKETS, MAX_PACKET) = .{},

    /// Packets handed over in each direction.
    packets_in: u64 = 0,
    packets_out: u64 = 0,
    diagnostics: Diagnostics = .{},
    integrity: Integrity = .valid,

    /// A transport reset the guest has not been told about yet.
    reset_pending: bool = false,

    /// Read a register. Accesses must be aligned words.
    pub fn load(self: *const VirtioVsock, offset: usize, size: usize) !u64 {
        if (offset >= mmio.CONFIG_BASE) {
            return mmio.configRead(std.mem.asBytes(&self.config), offset - mmio.CONFIG_BASE, size);
        }
        if (size != 4 or offset % 4 != 0) return error.AccessFault;
        return self.transport.load(offset);
    }

    /// Write a register, answering what the device must do next.
    pub fn store(self: *VirtioVsock, offset: usize, size: usize, value: u64) !mmio.Action {
        if (offset >= mmio.CONFIG_BASE) return .none; // configuration is read-only
        if (size != 4 or offset % 4 != 0) return error.AccessFault;
        const action = self.transport.store(offset, @truncate(value));
        switch (action) {
            .reset => self.reset(),
            else => {},
        }
        return action;
    }

    /// Which guest this is, as packets address it.
    pub fn guestCid(self: *const VirtioVsock) u64 {
        return self.config.guest_cid;
    }

    /// Set the context id. Before the driver comes up: a guest reads it once.
    pub fn setGuestCid(self: *VirtioVsock, cid: u64) void {
        self.config.guest_cid = cid;
    }

    /// Queue a packet for the guest, counting a refused packet once.
    pub fn pushPacket(self: *VirtioVsock, packet: []const u8) bool {
        if (!self.valid() or !self.fifosValid()) return false;
        if (!self.canPushPacket(packet.len)) {
            _ = self.add(&self.rx.dropped, 1, null, null);
            _ = self.add(&self.diagnostics.rx_enqueue_refused_packets, 1, null, null);
            return false;
        }
        return self.tryPushPacket(packet);
    }

    /// Whether one complete packet fits, without changing diagnostics.
    pub fn canPushPacket(self: *const VirtioVsock, len: usize) bool {
        return self.valid() and fifoValid(&self.rx) and self.rx.count < RX_PACKETS and len <= MAX_PACKET;
    }

    /// Queue one complete packet; a capacity refusal changes no state.
    pub fn tryPushPacket(self: *VirtioVsock, packet: []const u8) bool {
        if (!self.valid() or !self.fifosValid()) return false;
        if (!self.canPushPacket(packet.len)) return false;
        if (!self.rx.push(packet)) {
            self.invalidate(.{ .cause = .unexpected_enqueue_failure });
            return false;
        }
        return true;
    }

    /// Whether device integrity permits another service operation.
    pub fn valid(self: *const VirtioVsock) bool {
        return self.integrity == .valid;
    }

    /// Retain the first integrity failure through retries and driver reset.
    pub fn invalidate(self: *VirtioVsock, failure: Failure) void {
        if (self.valid()) self.integrity = .{ .invalid = failure };
    }

    /// The oldest packet the guest has sent, header included, or null when it
    /// has sent none. Valid until the next call that changes this device.
    pub fn peekPacket(self: *const VirtioVsock) ?[]const u8 {
        return self.tx.peek();
    }

    /// Drop the packet `peekPacket` answered, once it has been dealt with.
    pub fn dropPacket(self: *VirtioVsock) void {
        self.tx.pop();
    }

    /// Read a packet's header, or null when it is too short to have one.
    pub fn headerOf(packet: []const u8) ?PacketHeader {
        if (packet.len < PacketHeader.BYTES) return null;
        var h: PacketHeader = .{};
        @memcpy(std.mem.asBytes(&h)[0..PacketHeader.BYTES], packet[0..PacketHeader.BYTES]);
        return h;
    }

    /// Tell the guest every connection it had is gone. Delivered on the event
    /// queue as soon as the driver has posted a buffer for one.
    pub fn resetTransport(self: *VirtioVsock) void {
        self.reset_pending = true;
    }

    /// Serve the chains posted to `queue`.
    pub fn service(self: *VirtioVsock, queue: u32, g: Guest) void {
        if (queue >= NUM_QUEUES) return;
        var visit = self.beginService(g) orelse return;
        switch (queue) {
            RX_QUEUE => self.serviceRxBounded(g, &visit),
            TX_QUEUE => self.serviceTxBounded(g, &visit),
            EVENT_QUEUE => self.serviceEventBounded(g, &visit),
            else => {},
        }
    }

    /// Hand queued packets to the guest within the current available frontier.
    pub fn serviceRx(self: *VirtioVsock, g: Guest) void {
        var visit = self.beginService(g) orelse return;
        self.serviceRxBounded(g, &visit);
    }

    /// Validate active rings and capture one stopped-driver service frontier.
    pub fn beginService(self: *VirtioVsock, g: Guest) ?ServiceVisit {
        if (!self.valid() or !self.transport.driverOk()) return null;
        if (!self.fifosValid()) return null;
        var visit = ServiceVisit{ .entry_tx_packets = @intCast(self.tx.count) };
        for (self.transport.queues, 0..) |q, i| {
            visit.frontiers[i].queue = q;
            if (q.ready == 0) continue;
            if (q.ready != 1 or q.num == 0 or q.num > QUEUE_SIZE or !std.math.isPowerOfTwo(q.num) or
                q.desc % 16 != 0 or q.avail % 2 != 0 or q.used % 4 != 0)
            {
                self.invalidate(.{ .cause = .queue_invalid, .queue = @intCast(i) });
                return null;
            }
            const ranges = [_]Range{
                .{ .addr = q.desc, .len = @as(u64, q.num) * 16 },
                .{ .addr = q.avail, .len = 6 + @as(u64, q.num) * 2 },
                .{ .addr = q.used, .len = 6 + @as(u64, q.num) * 8 },
            };
            for (ranges) |range| {
                if (!range.mapped(g)) {
                    self.invalidate(.{ .cause = .queue_invalid, .queue = @intCast(i) });
                    return null;
                }
                for (visit.metadata[0..visit.metadata_count]) |other| {
                    if (range.overlaps(other)) {
                        self.invalidate(.{ .cause = .ring_alias, .queue = @intCast(i) });
                        return null;
                    }
                }
                visit.metadata[visit.metadata_count] = range;
                visit.metadata_count += 1;
            }
            const idx = g.read(u16, q.avail + 2).?;
            const distance = idx -% q.last_avail;
            if (distance > q.num or g.read(u16, q.used + 2).? != q.used_idx) {
                self.invalidate(.{ .cause = .queue_invalid, .queue = @intCast(i) });
                return null;
            }
            visit.frontiers[i] = .{ .active = true, .queue = q, .avail_idx = idx, .heads = distance };
        }
        if (!self.rxDestinationsDisjoint(g, &visit)) return null;
        return visit;
    }

    /// Check stable entry frontiers and actual primitive completion counts.
    pub fn validateService(self: *VirtioVsock, g: Guest, visit: *const ServiceVisit) bool {
        if (!self.valid()) return false;
        if (!self.transport.driverOk() or !self.fifosValid()) {
            self.invalidate(.{ .cause = .progress_bound });
            return false;
        }
        for (self.transport.queues, visit.frontiers, 0..) |q, frontier, i| {
            const start = frontier.queue;
            const completed = visit.completions(i);
            if (q.num != start.num or q.ready != start.ready or q.desc != start.desc or
                q.avail != start.avail or q.used != start.used or completed > frontier.heads or
                (i == EVENT_QUEUE and completed > 1) or
                q.last_avail != start.last_avail +% completed or q.used_idx != start.used_idx +% completed)
            {
                self.invalidate(.{ .cause = .progress_bound, .queue = @intCast(i) });
                return false;
            }
            if (frontier.active and (g.read(u16, q.avail + 2) != frontier.avail_idx or
                g.read(u16, q.used + 2) != q.used_idx))
            {
                self.invalidate(.{ .cause = .progress_bound, .queue = @intCast(i) });
                return false;
            }
        }
        return true;
    }

    /// Complete only RX heads captured by `beginService`, retaining unusable packets.
    pub fn serviceRxBounded(self: *VirtioVsock, g: Guest, visit: *ServiceVisit) void {
        if (!self.validateService(g, visit)) return;
        while (self.rx.peek()) |packet| {
            const head = self.nextHead(g, visit, RX_QUEUE) orelse return;
            const plan = self.writePlan(g, visit, RX_QUEUE, head);
            if (!self.valid()) return;
            if (plan) |p| {
                if (p.room >= packet.len) {
                    if (!self.add(&self.packets_in, 1, RX_QUEUE, head)) return;
                    p.fill(packet);
                    self.rx.pop();
                    self.complete(g, visit, RX_QUEUE, head, @intCast(packet.len));
                    continue;
                }
            }
            if (!self.add(&self.diagnostics.rx_unusable_heads, 1, RX_QUEUE, head)) return;
            self.complete(g, visit, RX_QUEUE, head, 0);
        }
    }

    /// True while a completion is unacknowledged.
    pub fn irqAsserted(self: *const VirtioVsock) bool {
        return self.transport.irqAsserted();
    }

    /// Admit only TX heads captured by `beginService`, stopping on full capacity.
    pub fn serviceTxBounded(self: *VirtioVsock, g: Guest, visit: *ServiceVisit) void {
        if (!self.validateService(g, visit)) return;
        while (self.tx.count < TX_PACKETS) {
            const head = self.nextHead(g, visit, TX_QUEUE) orelse return;
            const collected = collect(g, self.transport.queues[TX_QUEUE], head);
            switch (collected) {
                .packet => |packet| {
                    if (!self.add(&self.packets_out, 1, TX_QUEUE, head)) return;
                    if (!self.tx.push(packet.bytes[0..packet.len])) {
                        self.invalidate(.{ .cause = .unexpected_enqueue_failure, .queue = TX_QUEUE, .head = head });
                        return;
                    }
                    self.complete(g, visit, TX_QUEUE, head, 0);
                },
                .rejected => |rejection| {
                    const counter = if (rejection.cause == .tx_oversized)
                        &self.diagnostics.tx_rejected_oversize_packets
                    else
                        &self.diagnostics.tx_rejected_malformed_packets;
                    if (!self.add(counter, 1, TX_QUEUE, head)) return;
                    if (rejection.known_payload) |bytes| {
                        if (!self.add(&self.diagnostics.tx_rejected_known_payload_bytes, bytes, TX_QUEUE, head)) return;
                    } else {
                        if (!self.add(&self.diagnostics.tx_rejected_unknown_extent_packets, 1, TX_QUEUE, head)) return;
                    }
                    self.complete(g, visit, TX_QUEUE, head, 0);
                    self.invalidate(.{ .cause = rejection.cause, .queue = TX_QUEUE, .head = head });
                    return;
                },
            }
        }
    }

    /// Complete at most one pending event within the captured service frontier.
    pub fn serviceEventBounded(self: *VirtioVsock, g: Guest, visit: *ServiceVisit) void {
        if (!self.validateService(g, visit) or !self.reset_pending or visit.event_completions != 0) return;
        const head = self.nextHead(g, visit, EVENT_QUEUE) orelse return;
        const plan = self.writePlan(g, visit, EVENT_QUEUE, head) orelse return;
        if (plan.room < 4) return;
        var event: [4]u8 = undefined;
        std.mem.writeInt(u32, &event, EVENT_TRANSPORT_RESET, .little);
        plan.fill(&event);
        self.reset_pending = false;
        self.complete(g, visit, EVENT_QUEUE, head, 4);
    }

    const Range = struct {
        addr: u64,
        len: u64,

        fn mapped(self: Range, g: Guest) bool {
            if (@addWithOverflow(self.addr, self.len)[1] != 0) return false;
            return g.slice(self.addr, self.len) != null;
        }

        fn overlaps(self: Range, other: Range) bool {
            return self.len != 0 and other.len != 0 and
                self.addr < other.addr + other.len and other.addr < self.addr + self.len;
        }
    };

    const WritePlan = struct {
        buffers: [QUEUE_SIZE][]u8 = undefined,
        ranges: [QUEUE_SIZE]Range = undefined,
        n: usize = 0,
        room: u64 = 0,

        fn fill(self: WritePlan, msg: []const u8) void {
            var left = msg;
            for (self.buffers[0..self.n]) |buf| {
                if (left.len == 0) break;
                const take = @min(buf.len, left.len);
                @memcpy(buf[0..take], left[0..take]);
                left = left[take..];
            }
        }
    };

    fn rxDestinationsDisjoint(self: *VirtioVsock, g: Guest, visit: *const ServiceVisit) bool {
        const frontier = visit.frontiers[RX_QUEUE];
        if (!frontier.active) return true;
        const q = frontier.queue;
        var ranges: [QUEUE_SIZE]Range = undefined;
        var count: usize = 0;
        for (0..frontier.heads) |i| {
            const at = q.last_avail +% @as(u16, @intCast(i));
            const head = g.read(u16, q.avail + 4 + @as(u64, at % @as(u16, @intCast(q.num))) * 2).?;
            if (head >= q.num) {
                self.invalidate(.{ .cause = .queue_invalid, .queue = RX_QUEUE, .head = head });
                return false;
            }
            var c = q.chain(g, head);
            while (c.next()) |d| {
                const range = Range{ .addr = d.addr, .len = d.len };
                if (!d.flags.write or d.flags.indirect or d.flags._rsvd != 0 or range.len == 0 or !range.mapped(g)) continue;
                for (visit.metadata[0..visit.metadata_count]) |metadata| {
                    if (range.overlaps(metadata)) {
                        self.invalidate(.{ .cause = .ring_alias, .queue = RX_QUEUE, .head = head });
                        return false;
                    }
                }
                for (ranges[0..count]) |other| {
                    if (range.overlaps(other)) {
                        self.invalidate(.{ .cause = .ring_alias, .queue = RX_QUEUE, .head = head });
                        return false;
                    }
                }
                // A repeated nonempty descriptor aliases its first range.
                if (count == ranges.len) {
                    self.invalidate(.{ .cause = .progress_bound, .queue = RX_QUEUE, .head = head });
                    return false;
                }
                ranges[count] = range;
                count += 1;
            }
        }
        return true;
    }

    fn writePlan(self: *VirtioVsock, g: Guest, visit: *const ServiceVisit, queue: usize, head: u16) ?WritePlan {
        var plan = WritePlan{};
        var c = self.transport.queues[queue].chain(g, head);
        var bad = false;
        while (c.next()) |d| {
            const range = Range{ .addr = d.addr, .len = d.len };
            if (!d.flags.write or d.flags.indirect or d.flags._rsvd != 0 or !range.mapped(g)) {
                bad = true;
                continue;
            }
            for (visit.metadata[0..visit.metadata_count]) |metadata| {
                if (range.overlaps(metadata)) {
                    self.invalidate(.{ .cause = .ring_alias, .queue = @intCast(queue), .head = head });
                    return null;
                }
            }
            for (plan.ranges[0..plan.n]) |other| {
                if (range.overlaps(other)) {
                    self.invalidate(.{ .cause = .ring_alias, .queue = @intCast(queue), .head = head });
                    return null;
                }
            }
            plan.buffers[plan.n] = g.slice(d.addr, d.len).?;
            plan.ranges[plan.n] = range;
            const sum = @addWithOverflow(plan.room, d.len);
            if (sum[1] != 0) bad = true;
            plan.room = sum[0];
            plan.n += 1;
        }
        return if (bad or !c.done) null else plan;
    }

    const Rejection = struct { cause: FailureCause, known_payload: ?u64 = null };
    const StagedPacket = struct { bytes: [MAX_PACKET]u8, len: usize };
    const Collected = union(enum) { packet: StagedPacket, rejected: Rejection };

    fn collect(g: Guest, q: virtqueue.Queue, head: u16) Collected {
        var staged: [MAX_PACKET]u8 = undefined;
        var have: usize = 0;
        var capacity: u64 = 0;
        var bad = false;
        var c = q.chain(g, head);
        while (c.next()) |d| {
            const range = Range{ .addr = d.addr, .len = d.len };
            if (d.flags.write or d.flags.indirect or d.flags._rsvd != 0 or !range.mapped(g)) {
                bad = true;
                continue;
            }
            const buf = g.slice(d.addr, d.len).?;
            const sum = @addWithOverflow(capacity, d.len);
            if (sum[1] != 0) bad = true;
            capacity = sum[0];
            const take = @min(buf.len, staged.len - have);
            @memcpy(staged[have..][0..take], buf[0..take]);
            have += take;
        }
        if (bad or !c.done) return .{ .rejected = .{ .cause = .tx_bad_chain } };
        const header = headerOf(staged[0..have]) orelse return .{ .rejected = .{ .cause = .tx_short_header } };
        const total = @as(u64, PacketHeader.BYTES) + header.len;
        if (header.len > MAX_PACKET - PacketHeader.BYTES) {
            return .{ .rejected = .{ .cause = .tx_oversized, .known_payload = if (capacity >= total) header.len else null } };
        }
        if (capacity < total) return .{ .rejected = .{ .cause = .tx_short_payload } };
        return .{ .packet = .{ .bytes = staged, .len = @intCast(total) } };
    }

    fn nextHead(self: *VirtioVsock, g: Guest, visit: *const ServiceVisit, queue: usize) ?u16 {
        const frontier = visit.frontiers[queue];
        if (!frontier.active or visit.completions(queue) == frontier.heads) return null;
        const q = self.transport.queues[queue];
        const head = q.nextHead(g) orelse {
            self.invalidate(.{ .cause = .progress_bound, .queue = @intCast(queue) });
            return null;
        };
        if (head >= q.num) {
            self.invalidate(.{ .cause = .queue_invalid, .queue = @intCast(queue), .head = head });
            return null;
        }
        return head;
    }

    fn complete(self: *VirtioVsock, g: Guest, visit: *ServiceVisit, queue: usize, head: u16, len: u32) void {
        self.transport.complete(@intCast(queue), g, head, len);
        switch (queue) {
            RX_QUEUE => visit.rx_completions += 1,
            TX_QUEUE => visit.tx_completions += 1,
            else => visit.event_completions += 1,
        }
    }

    fn fifoValid(fifo: anytype) bool {
        if (fifo.count > @TypeOf(fifo.*).DEPTH or fifo.head >= @TypeOf(fifo.*).DEPTH) return false;
        for (0..fifo.count) |i| {
            if (fifo.lengths[(fifo.head + i) % @TypeOf(fifo.*).DEPTH] > MAX_PACKET) return false;
        }
        return true;
    }

    fn fifosValid(self: *VirtioVsock) bool {
        if (fifoValid(&self.rx) and fifoValid(&self.tx)) return true;
        self.invalidate(.{ .cause = .progress_bound });
        return false;
    }

    fn add(self: *VirtioVsock, counter: *u64, n: u64, queue: ?u8, head: ?u16) bool {
        const sum = @addWithOverflow(counter.*, n);
        counter.* = if (sum[1] != 0) std.math.maxInt(u64) else sum[0];
        if (sum[1] == 0) return true;
        self.invalidate(.{ .cause = .counter_overflow, .queue = queue, .head = head });
        return false;
    }

    fn reset(self: *VirtioVsock) void {
        // Guest device reset preserves diagnostics and integrity.
        const config = self.config;
        const in = self.packets_in;
        const out = self.packets_out;
        const diagnostics = self.diagnostics;
        const integrity = self.integrity;
        const rx_dropped = self.rx.dropped;
        const tx_dropped = self.tx.dropped;
        self.* = .{};
        self.config = config;
        self.packets_in = in;
        self.packets_out = out;
        self.diagnostics = diagnostics;
        self.integrity = integrity;
        self.rx.dropped = rx_dropped;
        self.tx.dropped = tx_dropped;
    }
};

// ---- tests ----------------------------------------------------------------

const testing = std.testing;
const BASE: u64 = 0;
const RX_DESC: u64 = 0x1000;
const RX_AVAIL: u64 = 0x2000;
const RX_USED: u64 = 0x3000;
const TX_DESC: u64 = 0x4000;
const TX_AVAIL: u64 = 0x5000;
const TX_USED: u64 = 0x6000;
const EV_DESC: u64 = 0x7000;
const EV_AVAIL: u64 = 0x8000;
const EV_USED: u64 = 0x9000;

/// Bring a queue up the way a driver does.
fn bringUp(v: *VirtioVsock, queue: u32, num: u32, desc: u32, avail: u32, used: u32) !void {
    _ = try v.store(0x030, 4, queue);
    _ = try v.store(0x038, 4, num);
    _ = try v.store(0x080, 4, desc);
    _ = try v.store(0x090, 4, avail);
    _ = try v.store(0x0a0, 4, used);
    _ = try v.store(0x044, 4, 1);
}

fn driverUp(v: *VirtioVsock) !void {
    _ = try v.store(0x070, 4, (mmio.Status{
        .acknowledge = true,
        .driver = true,
        .features_ok = true,
        .driver_ok = true,
    }).toBits());
}

fn postOne(g: Guest, desc: u64, avail: u64, addr: u64, len: u32, write: bool) void {
    g.write(u64, desc, addr);
    g.write(u32, desc + 8, len);
    g.write(u16, desc + 12, @bitCast(virtqueue.DescFlags{ .write = write }));
    g.write(u16, avail + 4, 0);
    g.write(u16, avail + 2, 1);
}

/// A packet with a header naming its ports and a payload after it.
fn packetOf(buf: []u8, src_port: u32, dst_port: u32, payload: []const u8) []u8 {
    const h = VirtioVsock.PacketHeader{
        .src_cid = 3,
        .dst_cid = VirtioVsock.HOST_CID,
        .src_port = src_port,
        .dst_port = dst_port,
        .len = @intCast(payload.len),
    };
    @memcpy(buf[0..VirtioVsock.PacketHeader.BYTES], std.mem.asBytes(&h)[0..VirtioVsock.PacketHeader.BYTES]);
    @memcpy(buf[VirtioVsock.PacketHeader.BYTES..][0..payload.len], payload);
    return buf[0 .. VirtioVsock.PacketHeader.BYTES + payload.len];
}

test "vsock: identifies as a modern virtio socket device" {
    var v = VirtioVsock{};
    try testing.expectEqual(@as(u64, mmio.MAGIC), try v.load(0x000, 4));
    try testing.expectEqual(@as(u64, 2), try v.load(0x004, 4));
    try testing.expectEqual(@as(u64, 19), try v.load(0x008, 4)); // socket
    try testing.expectEqual(@as(u64, QUEUE_SIZE), try v.load(0x034, 4));
}

test "vsock: the context id reads out of configuration space, and is read-only" {
    var v = VirtioVsock{};
    v.setGuestCid(42);
    try testing.expectEqual(@as(u64, 42), try v.load(0x100, 4));
    try testing.expectEqual(@as(u64, 0), try v.load(0x104, 4));
    _ = try v.store(0x100, 4, 7);
    try testing.expectEqual(@as(u64, 42), v.guestCid());
}

test "vsock: an unaligned or non-word access faults" {
    var v = VirtioVsock{};
    try testing.expectError(error.AccessFault, v.load(0x002, 4));
    try testing.expectError(error.AccessFault, v.load(0x000, 2));
    try testing.expectError(error.AccessFault, v.store(0x070, 1, 0));
}

test "vsock: a pushed packet fills a posted buffer whole" {
    const ram = try testing.allocator.alloc(u8, 0x10000);
    defer testing.allocator.free(ram);
    @memset(ram, 0);
    const g = Guest{ .memory = ram, .base = BASE };

    var v = VirtioVsock{};
    try bringUp(&v, RX_QUEUE, 4, RX_DESC, RX_AVAIL, RX_USED);
    try driverUp(&v);

    var buf: [VirtioVsock.MAX_PACKET]u8 = undefined;
    const packet = packetOf(&buf, 1024, 5000, "hello");
    try testing.expect(v.pushPacket(packet));
    postOne(g, RX_DESC, RX_AVAIL, 0xa000, 256, true);
    v.service(RX_QUEUE, g);

    try testing.expectEqualStrings("hello", ram[0xa000 + VirtioVsock.PacketHeader.BYTES ..][0..5]);
    const got = VirtioVsock.headerOf(ram[0xa000..][0..VirtioVsock.PacketHeader.BYTES]).?;
    try testing.expectEqual(@as(u32, 5000), got.dst_port);
    try testing.expectEqual(@as(u64, 1), v.packets_in);
    try testing.expectEqual(@as(?u32, @intCast(packet.len)), g.read(u32, RX_USED + 8));
}

test "vsock: a packet arriving before the driver is up waits" {
    const ram = try testing.allocator.alloc(u8, 0x10000);
    defer testing.allocator.free(ram);
    @memset(ram, 0);
    const g = Guest{ .memory = ram, .base = BASE };

    var v = VirtioVsock{};
    try bringUp(&v, RX_QUEUE, 4, RX_DESC, RX_AVAIL, RX_USED);
    var buf: [VirtioVsock.MAX_PACKET]u8 = undefined;
    try testing.expect(v.pushPacket(packetOf(&buf, 1, 2, "x")));
    postOne(g, RX_DESC, RX_AVAIL, 0xa000, 256, true);

    v.service(RX_QUEUE, g);
    try testing.expectEqual(@as(u64, 0), v.packets_in);

    try driverUp(&v);
    v.service(RX_QUEUE, g);
    try testing.expectEqual(@as(u64, 1), v.packets_in);
}

test "vsock: a buffer too small for the packet completes empty and retains it" {
    const ram = try testing.allocator.alloc(u8, 0x10000);
    defer testing.allocator.free(ram);
    @memset(ram, 0);
    const g = Guest{ .memory = ram, .base = BASE };

    var v = VirtioVsock{};
    try bringUp(&v, RX_QUEUE, 4, RX_DESC, RX_AVAIL, RX_USED);
    try driverUp(&v);
    var buf: [VirtioVsock.MAX_PACKET]u8 = undefined;
    try testing.expect(v.pushPacket(packetOf(&buf, 1, 2, "payload")));
    postOne(g, RX_DESC, RX_AVAIL, 0xa000, 8, true);

    v.service(RX_QUEUE, g);
    try testing.expectEqual(@as(u64, 0), v.packets_in);
    try testing.expectEqual(@as(?u32, 0), g.read(u32, RX_USED + 8));
    try testing.expectEqual(@as(?u16, 1), g.read(u16, RX_USED + 2));
    try testing.expectEqual(@as(usize, 1), v.rx.count);
    try testing.expectEqual(@as(u64, 1), v.diagnostics.rx_unusable_heads);
}

test "vsock: a transmitted chain becomes a packet the owner can take" {
    const ram = try testing.allocator.alloc(u8, 0x10000);
    defer testing.allocator.free(ram);
    @memset(ram, 0);
    const g = Guest{ .memory = ram, .base = BASE };

    var v = VirtioVsock{};
    try bringUp(&v, TX_QUEUE, 4, TX_DESC, TX_AVAIL, TX_USED);
    try driverUp(&v);

    var buf: [VirtioVsock.MAX_PACKET]u8 = undefined;
    const packet = packetOf(&buf, 1024, 5000, "outbound");
    @memcpy(ram[0xa000..][0..packet.len], packet);
    postOne(g, TX_DESC, TX_AVAIL, 0xa000, @intCast(packet.len), false);

    v.service(TX_QUEUE, g);

    const got = v.peekPacket().?;
    try testing.expectEqualStrings("outbound", got[VirtioVsock.PacketHeader.BYTES..]);
    try testing.expectEqual(@as(u32, 1024), VirtioVsock.headerOf(got).?.src_port);
    try testing.expectEqual(@as(u64, 1), v.packets_out);

    v.dropPacket();
    try testing.expectEqual(@as(?[]const u8, null), v.peekPacket());
}

test "vsock: a chain too short to hold a header carries no packet" {
    const ram = try testing.allocator.alloc(u8, 0x10000);
    defer testing.allocator.free(ram);
    @memset(ram, 0);
    const g = Guest{ .memory = ram, .base = BASE };

    var v = VirtioVsock{};
    try bringUp(&v, TX_QUEUE, 4, TX_DESC, TX_AVAIL, TX_USED);
    try driverUp(&v);
    postOne(g, TX_DESC, TX_AVAIL, 0xa000, VirtioVsock.PacketHeader.BYTES - 1, false);

    v.service(TX_QUEUE, g);
    try testing.expectEqual(@as(?[]const u8, null), v.peekPacket());
    try testing.expectEqual(@as(?u16, 1), g.read(u16, TX_USED + 2));
}

test "vsock: a transport reset reaches the guest on the event queue, once" {
    const ram = try testing.allocator.alloc(u8, 0x10000);
    defer testing.allocator.free(ram);
    @memset(ram, 0);
    const g = Guest{ .memory = ram, .base = BASE };

    var v = VirtioVsock{};
    try bringUp(&v, EVENT_QUEUE, 4, EV_DESC, EV_AVAIL, EV_USED);
    try driverUp(&v);
    postOne(g, EV_DESC, EV_AVAIL, 0xa000, 4, true);

    // Nothing to report yet.
    v.service(EVENT_QUEUE, g);
    try testing.expectEqual(@as(?u16, 0), g.read(u16, EV_USED + 2));

    v.resetTransport();
    v.service(EVENT_QUEUE, g);
    try testing.expectEqual(@as(?u32, EVENT_TRANSPORT_RESET), g.read(u32, 0xa000));
    try testing.expectEqual(@as(?u16, 1), g.read(u16, EV_USED + 2));

    // Reported once, not on every pass.
    v.service(EVENT_QUEUE, g);
    try testing.expectEqual(@as(?u16, 1), g.read(u16, EV_USED + 2));
}

test "vsock: a reset waiting for a buffer is delivered when one is posted" {
    const ram = try testing.allocator.alloc(u8, 0x10000);
    defer testing.allocator.free(ram);
    @memset(ram, 0);
    const g = Guest{ .memory = ram, .base = BASE };

    var v = VirtioVsock{};
    try bringUp(&v, EVENT_QUEUE, 4, EV_DESC, EV_AVAIL, EV_USED);
    try driverUp(&v);
    v.resetTransport();
    v.service(EVENT_QUEUE, g); // no buffer posted, so it waits

    postOne(g, EV_DESC, EV_AVAIL, 0xa000, 4, true);
    v.service(EVENT_QUEUE, g);
    try testing.expectEqual(@as(?u16, 1), g.read(u16, EV_USED + 2));
}

test "vsock: a kick on a queue this device does not have serves nothing" {
    const ram = try testing.allocator.alloc(u8, 0x10000);
    defer testing.allocator.free(ram);
    @memset(ram, 0);
    const g = Guest{ .memory = ram, .base = BASE };

    var v = VirtioVsock{};
    try bringUp(&v, RX_QUEUE, 4, RX_DESC, RX_AVAIL, RX_USED);
    try driverUp(&v);
    var buf: [VirtioVsock.MAX_PACKET]u8 = undefined;
    try testing.expect(v.pushPacket(packetOf(&buf, 1, 2, "x")));
    postOne(g, RX_DESC, RX_AVAIL, 0xa000, 256, true);

    v.service(9, g);
    try testing.expectEqual(@as(u64, 0), v.packets_in);
}

test "vsock: a reset clears the rings and keeps the address and the totals" {
    const ram = try testing.allocator.alloc(u8, 0x10000);
    defer testing.allocator.free(ram);
    @memset(ram, 0);
    const g = Guest{ .memory = ram, .base = BASE };

    var v = VirtioVsock{};
    v.setGuestCid(9);
    try bringUp(&v, RX_QUEUE, 4, RX_DESC, RX_AVAIL, RX_USED);
    try driverUp(&v);
    var buf: [VirtioVsock.MAX_PACKET]u8 = undefined;
    try testing.expect(v.pushPacket(packetOf(&buf, 1, 2, "x")));
    postOne(g, RX_DESC, RX_AVAIL, 0xa000, 256, true);
    v.service(RX_QUEUE, g);

    _ = try v.store(0x070, 4, 0);

    try testing.expectEqual(@as(u32, 0), v.transport.queues[RX_QUEUE].num);
    try testing.expectEqual(@as(u64, 9), v.guestCid());
    try testing.expectEqual(@as(u64, 1), v.packets_in);
}

fn descriptorAt(g: Guest, table: u64, index: u16, addr: u64, len: u32, flags: virtqueue.DescFlags, next: u16) void {
    const at = table + @as(u64, index) * virtqueue.DESC_BYTES;
    g.write(u64, at, addr);
    g.write(u32, at + 8, len);
    g.write(u16, at + 12, @bitCast(flags));
    g.write(u16, at + 14, next);
}

fn postHead(g: Guest, avail: u64, slot: u16, head: u16, idx: u16) void {
    g.write(u16, avail + 4 + @as(u64, slot) * 2, head);
    g.write(u16, avail + 2, idx);
}

test "vsock integrity: full TX leaves the ninth head pending without FIFO refusal" {
    var ram: [0x20000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, TX_QUEUE, 16, TX_DESC, TX_AVAIL, TX_USED);
    try driverUp(&v);
    for (0..12) |i| {
        const addr = 0xa000 + @as(u64, @intCast(i)) * 128;
        const packet = packetOf(ram[@intCast(addr)..][0..128], @intCast(i), 2, "data");
        descriptorAt(g, TX_DESC, @intCast(i), addr, @intCast(packet.len), .{}, 0);
        postHead(g, TX_AVAIL, @intCast(i), @intCast(i), @intCast(i + 1));
    }
    v.service(TX_QUEUE, g);
    try testing.expectEqual(@as(u16, 8), v.transport.queues[TX_QUEUE].last_avail);
    try testing.expectEqual(@as(u64, 0), v.tx.dropped);
    v.service(TX_QUEUE, g);
    try testing.expectEqual(@as(u16, 8), v.transport.queues[TX_QUEUE].last_avail);
    try testing.expectEqual(@as(u64, 0), v.tx.dropped);
    for (0..12) |i| {
        const packet = v.peekPacket().?;
        try testing.expectEqual(@as(u32, @intCast(i)), VirtioVsock.headerOf(packet).?.src_port);
        v.dropPacket();
        v.service(TX_QUEUE, g);
    }
    try testing.expectEqual(@as(u64, 12), v.packets_out);
    try testing.expectEqual(@as(u16, 12), v.transport.queues[TX_QUEUE].used_idx);
    try testing.expectEqual(@as(usize, 0), v.tx.count);
}

test "vsock integrity: descriptor capacity larger than the declared payload is accepted exactly" {
    var ram: [0x20000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, TX_QUEUE, 4, TX_DESC, TX_AVAIL, TX_USED);
    try driverUp(&v);
    const packet = packetOf(ram[0xa000..][0..128], 1, 2, "data");
    postOne(g, TX_DESC, TX_AVAIL, 0xa000, 8192, false);
    v.service(TX_QUEUE, g);
    try testing.expectEqualSlices(u8, packet, v.peekPacket().?);
    try testing.expectEqual(@as(u64, 1), v.packets_out);
}

test "vsock integrity: oversized declared payload exposes no clipped packet" {
    var ram: [0x20000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, TX_QUEUE, 4, TX_DESC, TX_AVAIL, TX_USED);
    try driverUp(&v);
    _ = packetOf(ram[0xa000..][0..8192], 1, 2, ram[0x10000..][0..4097]);
    postOne(g, TX_DESC, TX_AVAIL, 0xa000, VirtioVsock.PacketHeader.BYTES + 4097, false);
    v.service(TX_QUEUE, g);
    try testing.expectEqual(@as(usize, 0), v.tx.count);
    try testing.expectEqual(@as(u64, 0), v.packets_out);
    try testing.expectEqual(@as(u16, 1), v.transport.queues[TX_QUEUE].used_idx);
}

test "vsock integrity: insufficient declared payload exposes no packet" {
    var ram: [0x10000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, TX_QUEUE, 4, TX_DESC, TX_AVAIL, TX_USED);
    try driverUp(&v);
    const packet = packetOf(ram[0xa000..][0..128], 1, 2, "data");
    postOne(g, TX_DESC, TX_AVAIL, 0xa000, @intCast(packet.len - 1), false);
    v.service(TX_QUEUE, g);
    try testing.expectEqual(@as(usize, 0), v.tx.count);
    try testing.expectEqual(@as(u16, 1), v.transport.queues[TX_QUEUE].used_idx);
}

fn txTailControl(case: usize) !void {
    var ram: [0x10000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, TX_QUEUE, 4, TX_DESC, TX_AVAIL, TX_USED);
    try driverUp(&v);
    const packet = packetOf(ram[0xa000..][0..128], 1, 2, "data");
    descriptorAt(g, TX_DESC, 0, 0xa000, @intCast(packet.len), .{ .next = true }, 1);
    switch (case) {
        0 => descriptorAt(g, TX_DESC, 1, 0xb000, 1, .{ .write = true }, 0),
        1 => descriptorAt(g, TX_DESC, 1, 0x10000, 1, .{}, 0),
        2 => descriptorAt(g, TX_DESC, 1, 0xb000, 1, .{ .indirect = true }, 0),
        else => descriptorAt(g, TX_DESC, 1, 0xb000, 1, .{ .next = true }, 4),
    }
    postHead(g, TX_AVAIL, 0, 0, 1);
    v.service(TX_QUEUE, g);
    try testing.expectEqual(@as(usize, 0), v.tx.count);
    try testing.expectEqual(@as(u16, 1), v.transport.queues[TX_QUEUE].used_idx);
}

test "vsock integrity: TX rejects a writable tail" {
    try txTailControl(0);
}

test "vsock integrity: TX rejects an unmapped tail" {
    try txTailControl(1);
}

test "vsock integrity: TX rejects an indirect tail" {
    try txTailControl(2);
}

test "vsock integrity: TX rejects an unterminated tail" {
    try txTailControl(3);
}

test "vsock integrity: short RX retains the packet and delivers on the next sufficient head" {
    var ram: [0x10000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, RX_QUEUE, 4, RX_DESC, RX_AVAIL, RX_USED);
    try driverUp(&v);
    var buf: [128]u8 = undefined;
    const packet = packetOf(&buf, 1, 2, "payload");
    try testing.expect(v.pushPacket(packet));
    descriptorAt(g, RX_DESC, 0, 0xa000, 8, .{ .write = true }, 0);
    descriptorAt(g, RX_DESC, 1, 0xb000, 128, .{ .write = true }, 0);
    postHead(g, RX_AVAIL, 0, 0, 1);
    v.service(RX_QUEUE, g);
    try testing.expectEqual(@as(usize, 1), v.rx.count);
    try testing.expectEqual(@as(u8, 0), ram[0xa000]);
    v.service(RX_QUEUE, g);
    try testing.expectEqual(@as(u16, 1), v.transport.queues[RX_QUEUE].used_idx);
    postHead(g, RX_AVAIL, 1, 1, 2);
    v.service(RX_QUEUE, g);
    try testing.expectEqualSlices(u8, packet, ram[0xb000..][0..packet.len]);
    try testing.expectEqual(@as(u64, 1), v.packets_in);
    try testing.expectEqual(@as(u16, 2), v.transport.queues[RX_QUEUE].used_idx);
    try testing.expectEqual(@as(usize, 0), v.rx.count);
}

fn rxTailControl(case: usize) !void {
    var ram: [0x10000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, RX_QUEUE, 4, RX_DESC, RX_AVAIL, RX_USED);
    try driverUp(&v);
    var buf: [128]u8 = undefined;
    try testing.expect(v.pushPacket(packetOf(&buf, 1, 2, "payload")));
    descriptorAt(g, RX_DESC, 0, 0xa000, 128, .{ .write = true, .next = true }, 1);
    switch (case) {
        0 => descriptorAt(g, RX_DESC, 1, 0xb000, 1, .{}, 0),
        1 => descriptorAt(g, RX_DESC, 1, 0x10000, 1, .{ .write = true }, 0),
        else => descriptorAt(g, RX_DESC, 1, 0xb000, 1, .{ .write = true, .next = true }, 4),
    }
    postHead(g, RX_AVAIL, 0, 0, 1);
    v.service(RX_QUEUE, g);
    try testing.expectEqual(@as(u8, 0), ram[0xa000]);
    try testing.expectEqual(@as(usize, 1), v.rx.count);
    try testing.expectEqual(@as(u16, 1), v.transport.queues[RX_QUEUE].used_idx);
    try testing.expectEqual(@as(?u32, 0), g.read(u32, RX_USED + 8));
}

test "vsock integrity: RX rejects a readable tail before writing" {
    try rxTailControl(0);
}

test "vsock integrity: RX rejects an unmapped tail before writing" {
    try rxTailControl(1);
}

test "vsock integrity: RX rejects an unterminated tail before writing" {
    try rxTailControl(2);
}

fn ringControl(case: usize) !void {
    var ram: [0x10000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, TX_QUEUE, 4, TX_DESC, TX_AVAIL, TX_USED);
    try driverUp(&v);
    const packet = packetOf(ram[0xa000..][0..128], 1, 2, "payload");
    postOne(g, TX_DESC, TX_AVAIL, 0xa000, @intCast(packet.len), false);
    switch (case) {
        0 => g.write(u16, TX_AVAIL + 2, 5),
        1 => v.transport.queues[TX_QUEUE].num = 3,
        2 => v.transport.queues[TX_QUEUE].used = 0x10000,
        else => postHead(g, TX_AVAIL, 0, 4, 1),
    }
    v.service(TX_QUEUE, g);
    try testing.expectEqual(@as(u16, 0), v.transport.queues[TX_QUEUE].used_idx);
    try testing.expectEqual(@as(usize, 0), v.tx.count);
}

test "vsock integrity: invalid available distance completes nothing" {
    try ringControl(0);
}

test "vsock integrity: invalid queue depth completes nothing" {
    try ringControl(1);
}

test "vsock integrity: unmapped used ring completes nothing" {
    try ringControl(2);
}

test "vsock integrity: out of range head completes nothing" {
    try ringControl(3);
}

test "vsock integrity: active queue metadata ranges cannot alias" {
    var ram: [0x10000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, RX_QUEUE, 4, RX_DESC, RX_AVAIL, RX_USED);
    try bringUp(&v, TX_QUEUE, 4, TX_DESC, TX_AVAIL, RX_AVAIL);
    try driverUp(&v);
    const packet = packetOf(ram[0xa000..][0..128], 1, 2, "payload");
    postOne(g, TX_DESC, TX_AVAIL, 0xa000, @intCast(packet.len), false);
    v.service(TX_QUEUE, g);
    try testing.expectEqual(@as(u16, 0), v.transport.queues[TX_QUEUE].used_idx);
    try testing.expectEqual(@as(usize, 0), v.tx.count);
}

fn rxAliasControl(case: usize) !void {
    var ram: [0x10000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, RX_QUEUE, 4, RX_DESC, RX_AVAIL, RX_USED);
    try driverUp(&v);
    var buf: [128]u8 = undefined;
    try testing.expect(v.pushPacket(packetOf(&buf, 1, 2, "payload")));
    if (case == 0) {
        postOne(g, RX_DESC, RX_AVAIL, RX_AVAIL, 128, true);
    } else {
        descriptorAt(g, RX_DESC, 0, 0xa000, 40, .{ .write = true, .next = true }, 1);
        descriptorAt(g, RX_DESC, 1, 0xa000, 40, .{ .write = true }, 0);
        postHead(g, RX_AVAIL, 0, 0, 1);
    }
    v.service(RX_QUEUE, g);
    try testing.expectEqual(@as(u16, 0), v.transport.queues[RX_QUEUE].used_idx);
    try testing.expectEqual(@as(usize, 1), v.rx.count);
    try testing.expectEqual(@as(u64, 0), v.packets_in);
}

test "vsock integrity: RX destination cannot alias metadata" {
    try rxAliasControl(0);
}

test "vsock integrity: RX destinations cannot overlap" {
    try rxAliasControl(1);
}

test "vsock integrity: TX diagnostic overflow saturates before admission" {
    var ram: [0x10000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, TX_QUEUE, 4, TX_DESC, TX_AVAIL, TX_USED);
    try driverUp(&v);
    const packet = packetOf(ram[0xa000..][0..128], 1, 2, "data");
    postOne(g, TX_DESC, TX_AVAIL, 0xa000, @intCast(packet.len), false);
    v.packets_out = std.math.maxInt(u64);
    v.service(TX_QUEUE, g);
    try testing.expectEqual(std.math.maxInt(u64), v.packets_out);
    try testing.expectEqual(@as(usize, 0), v.tx.count);
    try testing.expectEqual(@as(u16, 0), v.transport.queues[TX_QUEUE].used_idx);
}

test "vsock integrity: RX diagnostic overflow saturates before writing" {
    var ram: [0x10000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, RX_QUEUE, 4, RX_DESC, RX_AVAIL, RX_USED);
    try driverUp(&v);
    var buf: [128]u8 = undefined;
    try testing.expect(v.pushPacket(packetOf(&buf, 1, 2, "data")));
    postOne(g, RX_DESC, RX_AVAIL, 0xa000, 128, true);
    v.packets_in = std.math.maxInt(u64);
    v.service(RX_QUEUE, g);
    try testing.expectEqual(std.math.maxInt(u64), v.packets_in);
    try testing.expectEqual(@as(u8, 0), ram[0xa000]);
    try testing.expectEqual(@as(usize, 1), v.rx.count);
    try testing.expectEqual(@as(u16, 0), v.transport.queues[RX_QUEUE].used_idx);
}

test "vsock integrity: RX refusal overflow saturates instead of wrapping" {
    var v = VirtioVsock{};
    for (0..RX_PACKETS) |_| try testing.expect(v.pushPacket("x"));
    v.rx.dropped = std.math.maxInt(u64);
    try testing.expect(!v.pushPacket("x"));
    try testing.expectEqual(std.math.maxInt(u64), v.rx.dropped);
}

test "vsock integrity: transactional reply capacity retries change no loss counter" {
    var v = VirtioVsock{};
    for (0..RX_PACKETS) |_| try testing.expect(v.tryPushPacket("x"));
    for (0..4) |_| {
        try testing.expect(!v.canPushPacket(1));
        try testing.expect(!v.tryPushPacket("x"));
    }
    try testing.expectEqual(@as(u64, 0), v.rx.dropped);
    try testing.expectEqual(@as(u64, 0), v.diagnostics.rx_enqueue_refused_packets);
    try testing.expect(v.valid());
    v.rx.pop();
    try testing.expect(v.canPushPacket(VirtioVsock.MAX_PACKET));
    try testing.expect(v.tryPushPacket("y"));
    try testing.expect(!v.canPushPacket(VirtioVsock.MAX_PACKET + 1));
}

test "vsock integrity: rejection records exact units retains the first failure and survives reset" {
    var ram: [0x20000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, TX_QUEUE, 4, TX_DESC, TX_AVAIL, TX_USED);
    try driverUp(&v);
    _ = packetOf(ram[0xa000..][0..8192], 1, 2, ram[0x10000..][0..4097]);
    postOne(g, TX_DESC, TX_AVAIL, 0xa000, VirtioVsock.MAX_PACKET + 1, false);
    v.service(TX_QUEUE, g);
    const expected = VirtioVsock.Failure{ .cause = .tx_oversized, .queue = TX_QUEUE, .head = 0 };
    try testing.expectEqual(expected, v.integrity.invalid);
    try testing.expectEqual(@as(u64, 1), v.diagnostics.tx_rejected_oversize_packets);
    try testing.expectEqual(@as(u64, 4097), v.diagnostics.tx_rejected_known_payload_bytes);
    try testing.expectEqual(@as(u64, 0), v.diagnostics.tx_rejected_unknown_extent_packets);
    v.invalidate(.{ .cause = .progress_bound });
    v.service(TX_QUEUE, g);
    try testing.expectEqual(@as(u16, 1), v.transport.queues[TX_QUEUE].used_idx);
    _ = try v.store(0x070, 4, 0);
    try testing.expect(!v.valid());
    try testing.expectEqual(expected, v.integrity.invalid);
    try testing.expectEqual(@as(u64, 4097), v.diagnostics.tx_rejected_known_payload_bytes);
    try bringUp(&v, TX_QUEUE, 4, TX_DESC, TX_AVAIL, TX_USED);
    try driverUp(&v);
    v.service(TX_QUEUE, g);
    try testing.expectEqual(@as(u16, 0), v.transport.queues[TX_QUEUE].used_idx);
}

test "vsock integrity: malformed rejection has unknown extent and stops before the next head" {
    var ram: [0x10000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, TX_QUEUE, 4, TX_DESC, TX_AVAIL, TX_USED);
    try driverUp(&v);
    descriptorAt(g, TX_DESC, 0, 0xa000, 43, .{}, 0);
    const packet = packetOf(ram[0xb000..][0..128], 1, 2, "data");
    descriptorAt(g, TX_DESC, 1, 0xb000, @intCast(packet.len), .{}, 0);
    postHead(g, TX_AVAIL, 0, 0, 1);
    postHead(g, TX_AVAIL, 1, 1, 2);
    var visit = v.beginService(g).?;
    v.serviceTxBounded(g, &visit);
    try testing.expectEqual(@as(u16, 1), visit.tx_completions);
    try testing.expectEqual(@as(usize, 0), v.tx.count);
    try testing.expectEqual(VirtioVsock.FailureCause.tx_short_header, v.integrity.invalid.cause);
    try testing.expectEqual(@as(u64, 1), v.diagnostics.tx_rejected_malformed_packets);
    try testing.expectEqual(@as(u64, 1), v.diagnostics.tx_rejected_unknown_extent_packets);
    try testing.expectEqual(@as(u64, 0), v.diagnostics.tx_rejected_known_payload_bytes);
}

test "vsock integrity: a split header and exact 4096 payload traverse their full chain" {
    var ram: [0x20000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, TX_QUEUE, 8, TX_DESC, TX_AVAIL, TX_USED);
    try driverUp(&v);
    var source: [VirtioVsock.MAX_PACKET]u8 = undefined;
    const packet = packetOf(&source, 1, 2, ram[0x10000..][0..4096]);
    @memcpy(ram[0xa000..][0..17], packet[0..17]);
    @memcpy(ram[0xb000..][0..30], packet[17..47]);
    @memcpy(ram[0xc000..][0 .. packet.len - 47], packet[47..]);
    descriptorAt(g, TX_DESC, 0, 0xa000, 17, .{ .next = true }, 1);
    descriptorAt(g, TX_DESC, 1, 0xb000, 30, .{ .next = true }, 2);
    descriptorAt(g, TX_DESC, 2, 0xc000, @intCast(packet.len - 47), .{ .next = true }, 3);
    descriptorAt(g, TX_DESC, 3, 0xe000, 8, .{}, 0);
    postHead(g, TX_AVAIL, 0, 0, 1);
    var visit = v.beginService(g).?;
    v.serviceTxBounded(g, &visit);
    try testing.expect(v.valid());
    try testing.expectEqualSlices(u8, packet, v.peekPacket().?);
    try testing.expectEqual(@as(u16, 1), visit.tx_completions);
    try testing.expect(v.validateService(g, &visit));
    v.serviceTxBounded(g, &visit);
    try testing.expectEqual(@as(u16, 1), visit.tx_completions);
}

test "vsock integrity: bounded visit accounts repeated short RX and a single event completion" {
    var ram: [0x10000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, RX_QUEUE, 4, RX_DESC, RX_AVAIL, RX_USED);
    try bringUp(&v, EVENT_QUEUE, 4, EV_DESC, EV_AVAIL, EV_USED);
    try driverUp(&v);
    var buf: [128]u8 = undefined;
    const packet = packetOf(&buf, 1, 2, "data");
    try testing.expect(v.pushPacket(packet));
    for (0..3) |i| {
        descriptorAt(g, RX_DESC, @intCast(i), 0xa000 + @as(u64, @intCast(i)) * 128, 8, .{ .write = true }, 0);
        postHead(g, RX_AVAIL, @intCast(i), @intCast(i), @intCast(i + 1));
    }
    descriptorAt(g, RX_DESC, 3, 0xb000, 128, .{ .write = true }, 0);
    postHead(g, RX_AVAIL, 3, 3, 4);
    postOne(g, EV_DESC, EV_AVAIL, 0xc000, 4, true);
    v.resetTransport();
    var visit = v.beginService(g).?;
    try testing.expectEqual(@as(u16, 4), visit.frontiers[RX_QUEUE].heads);
    v.serviceRxBounded(g, &visit);
    v.serviceEventBounded(g, &visit);
    try testing.expectEqual(@as(u16, 4), visit.rx_completions);
    try testing.expectEqual(@as(u16, 1), visit.event_completions);
    try testing.expectEqual(@as(u64, 3), v.diagnostics.rx_unusable_heads);
    try testing.expectEqual(@as(u64, 1), v.packets_in);
    try testing.expectEqualSlices(u8, packet, ram[0xb000..][0..packet.len]);
    v.serviceRxBounded(g, &visit);
    v.resetTransport();
    v.serviceEventBounded(g, &visit);
    try testing.expectEqual(@as(u16, 4), visit.rx_completions);
    try testing.expectEqual(@as(u16, 1), visit.event_completions);
    try testing.expect(v.reset_pending);
    try testing.expect(v.validateService(g, &visit));
}

test "vsock integrity: changed entry frontier fails even after a no-progress service" {
    var ram: [0x10000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, RX_QUEUE, 4, RX_DESC, RX_AVAIL, RX_USED);
    try driverUp(&v);
    var visit = v.beginService(g).?;
    v.serviceRxBounded(g, &visit);
    try testing.expectEqual(@as(u16, 0), visit.rx_completions);
    g.write(u16, RX_AVAIL + 2, 1);
    try testing.expect(!v.validateService(g, &visit));
    try testing.expectEqual(VirtioVsock.FailureCause.progress_bound, v.integrity.invalid.cause);
    try testing.expectEqual(@as(u16, 0), visit.rx_completions);
}

test "vsock integrity: used and available indices wrap within a bounded visit" {
    var ram: [0x10000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, TX_QUEUE, 4, TX_DESC, TX_AVAIL, TX_USED);
    try driverUp(&v);
    v.transport.queues[TX_QUEUE].last_avail = 65535;
    v.transport.queues[TX_QUEUE].used_idx = 65535;
    g.write(u16, TX_USED + 2, 65535);
    const packet = packetOf(ram[0xa000..][0..128], 1, 2, "data");
    descriptorAt(g, TX_DESC, 0, 0xa000, @intCast(packet.len), .{}, 0);
    postHead(g, TX_AVAIL, 3, 0, 0);
    var visit = v.beginService(g).?;
    try testing.expectEqual(@as(u16, 1), visit.frontiers[TX_QUEUE].heads);
    v.serviceTxBounded(g, &visit);
    try testing.expectEqual(@as(u16, 0), v.transport.queues[TX_QUEUE].used_idx);
    try testing.expectEqual(@as(u16, 1), visit.tx_completions);
    try testing.expectEqual(@as(?u32, 0), g.read(u32, TX_USED + 4 + 3 * 8));
    try testing.expect(v.validateService(g, &visit));
}

test "vsock integrity: restored FIFO geometry and lengths fail before a packet view" {
    for (0..3) |case| {
        var ram: [0x10000]u8 = @splat(0);
        const g = Guest{ .memory = &ram, .base = 0 };
        var v = VirtioVsock{};
        try driverUp(&v);
        switch (case) {
            0 => v.tx.count = TX_PACKETS + 1,
            1 => v.rx.head = RX_PACKETS,
            else => {
                v.tx.count = 1;
                v.tx.lengths[0] = VirtioVsock.MAX_PACKET + 1;
            },
        }
        try testing.expectEqual(@as(?VirtioVsock.ServiceVisit, null), v.beginService(g));
        try testing.expectEqual(VirtioVsock.FailureCause.progress_bound, v.integrity.invalid.cause);
    }
}

test "vsock integrity: maximum entry frontiers account 200 primitives and one event" {
    var ram: [0x20000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, RX_QUEUE, QUEUE_SIZE, RX_DESC, RX_AVAIL, RX_USED);
    try bringUp(&v, TX_QUEUE, QUEUE_SIZE, TX_DESC, TX_AVAIL, TX_USED);
    try bringUp(&v, EVENT_QUEUE, QUEUE_SIZE, EV_DESC, EV_AVAIL, EV_USED);
    try driverUp(&v);
    const packet = packetOf(ram[0xa000..][0..128], 1, 2, "data");
    for (0..TX_PACKETS) |_| try testing.expect(v.tx.push(packet));
    try testing.expect(v.tryPushPacket(packet));
    for (0..QUEUE_SIZE) |i| {
        descriptorAt(g, RX_DESC, @intCast(i), 0xb000 + @as(u64, @intCast(i)) * 16, 8, .{ .write = true }, 0);
        postHead(g, RX_AVAIL, @intCast(i), @intCast(i), @intCast(i + 1));
        descriptorAt(g, TX_DESC, @intCast(i), 0xa000, @intCast(packet.len), .{}, 0);
        postHead(g, TX_AVAIL, @intCast(i), @intCast(i), @intCast(i + 1));
    }
    postOne(g, EV_DESC, EV_AVAIL, 0xc000, 4, true);
    v.resetTransport();
    var visit = v.beginService(g).?;
    var pops: u16 = 0;
    for (0..TX_PACKETS + 2) |_| {
        v.serviceRxBounded(g, &visit);
        v.serviceTxBounded(g, &visit);
        while (v.peekPacket() != null) {
            v.dropPacket();
            pops += 1;
        }
        v.serviceEventBounded(g, &visit);
        try testing.expect(v.validateService(g, &visit));
        try testing.expectEqual(@as(usize, visit.entry_tx_packets + visit.tx_completions - pops), v.tx.count);
    }
    try testing.expectEqual(@as(u16, 64), visit.tx_completions);
    try testing.expectEqual(@as(u16, 64), visit.rx_completions);
    try testing.expectEqual(@as(u16, 72), pops);
    try testing.expectEqual(@as(u16, 200), visit.tx_completions + visit.rx_completions + pops);
    try testing.expectEqual(@as(u16, 1), visit.event_completions);
    try testing.expectEqual(@as(u64, 64), v.diagnostics.rx_unusable_heads);
    try testing.expectEqual(@as(usize, 1), v.rx.count);
    try testing.expect(v.valid());
}

test "vsock integrity: malformed and unusable diagnostics saturate with a named failure" {
    for (0..3) |case| {
        var ram: [0x10000]u8 = @splat(0);
        const g = Guest{ .memory = &ram, .base = 0 };
        var v = VirtioVsock{};
        const queue: u32 = if (case == 2) RX_QUEUE else TX_QUEUE;
        try bringUp(&v, queue, 4, if (case == 2) RX_DESC else TX_DESC, if (case == 2) RX_AVAIL else TX_AVAIL, if (case == 2) RX_USED else TX_USED);
        try driverUp(&v);
        switch (case) {
            0 => v.diagnostics.tx_rejected_malformed_packets = std.math.maxInt(u64),
            1 => v.diagnostics.tx_rejected_unknown_extent_packets = std.math.maxInt(u64),
            else => {
                v.diagnostics.rx_unusable_heads = std.math.maxInt(u64);
                try testing.expect(v.tryPushPacket("payload"));
            },
        }
        postOne(g, if (case == 2) RX_DESC else TX_DESC, if (case == 2) RX_AVAIL else TX_AVAIL, 0xa000, 1, case == 2);
        v.service(queue, g);
        try testing.expectEqual(VirtioVsock.FailureCause.counter_overflow, v.integrity.invalid.cause);
        try testing.expectEqual(@as(u16, 0), v.transport.queues[queue].used_idx);
        const counter = switch (case) {
            0 => v.diagnostics.tx_rejected_malformed_packets,
            1 => v.diagnostics.tx_rejected_unknown_extent_packets,
            else => v.diagnostics.rx_unusable_heads,
        };
        try testing.expectEqual(std.math.maxInt(u64), counter);
        _ = try v.store(0x070, 4, 0);
        try testing.expectEqual(VirtioVsock.FailureCause.counter_overflow, v.integrity.invalid.cause);
    }
}

fn fullPayloadTailControl(case: usize) !void {
    var ram: [0x20000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, TX_QUEUE, 4, TX_DESC, TX_AVAIL, TX_USED);
    try driverUp(&v);
    const packet = packetOf(ram[0xa000..][0..8192], 1, 2, ram[0x10000..][0..4096]);
    descriptorAt(g, TX_DESC, 0, 0xa000, @intCast(packet.len), .{ .next = true }, 1);
    switch (case) {
        0 => descriptorAt(g, TX_DESC, 1, 0xc000, 1, .{ .write = true }, 0),
        1 => descriptorAt(g, TX_DESC, 1, 0x20000, 1, .{}, 0),
        else => descriptorAt(g, TX_DESC, 1, 0xc000, 1, .{ .next = true }, 0),
    }
    postHead(g, TX_AVAIL, 0, 0, 1);
    v.service(TX_QUEUE, g);
    try testing.expectEqual(@as(usize, 0), v.tx.count);
    try testing.expectEqual(@as(u64, 0), v.packets_out);
    try testing.expectEqual(@as(u16, 1), v.transport.queues[TX_QUEUE].used_idx);
}

test "vsock integrity: full payload rejects a writable tail" {
    try fullPayloadTailControl(0);
}

test "vsock integrity: full payload rejects an unmapped tail" {
    try fullPayloadTailControl(1);
}

test "vsock integrity: full payload rejects a cyclic tail" {
    try fullPayloadTailControl(2);
}

fn crossHeadRxAliasControl(offset: u64) !void {
    var ram: [0x10000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, RX_QUEUE, 4, RX_DESC, RX_AVAIL, RX_USED);
    try driverUp(&v);
    var first: [128]u8 = undefined;
    var second: [128]u8 = undefined;
    try testing.expect(v.tryPushPacket(packetOf(&first, 1, 2, "first")));
    try testing.expect(v.tryPushPacket(packetOf(&second, 3, 4, "second")));
    descriptorAt(g, RX_DESC, 0, 0xa000, 128, .{ .write = true }, 0);
    descriptorAt(g, RX_DESC, 1, 0xa000 + offset, 128, .{ .write = true }, 0);
    postHead(g, RX_AVAIL, 0, 0, 1);
    postHead(g, RX_AVAIL, 1, 1, 2);
    v.service(RX_QUEUE, g);
    try testing.expectEqual(@as(u16, 0), v.transport.queues[RX_QUEUE].used_idx);
    try testing.expectEqual(@as(u16, 0), v.transport.queues[RX_QUEUE].last_avail);
    try testing.expectEqual(@as(u64, 0), v.packets_in);
    try testing.expectEqual(@as(u64, 0), v.diagnostics.rx_unusable_heads);
    try testing.expectEqual(@as(usize, 2), v.rx.count);
    try testing.expectEqualSlices(u8, first[0 .. VirtioVsock.PacketHeader.BYTES + 5], v.rx.peek().?);
    try testing.expectEqual(@as(u8, 0), ram[0xa000]);
    try testing.expectEqual(VirtioVsock.FailureCause.ring_alias, v.integrity.invalid.cause);
    try testing.expectEqual(@as(?u8, RX_QUEUE), v.integrity.invalid.queue);
    try testing.expectEqual(@as(?u16, 1), v.integrity.invalid.head);
}

test "vsock integrity: outstanding RX heads cannot share a destination" {
    try crossHeadRxAliasControl(0);
}

test "vsock integrity: outstanding RX heads cannot partially overlap destinations" {
    try crossHeadRxAliasControl(64);
}

test "vsock integrity: outstanding RX heads with adjacent destinations deliver exactly once" {
    var ram: [0x10000]u8 = @splat(0);
    const g = Guest{ .memory = &ram, .base = 0 };
    var v = VirtioVsock{};
    try bringUp(&v, RX_QUEUE, 4, RX_DESC, RX_AVAIL, RX_USED);
    try driverUp(&v);
    var first: [128]u8 = undefined;
    var second: [128]u8 = undefined;
    const one = packetOf(&first, 1, 2, "first");
    const two = packetOf(&second, 3, 4, "second");
    try testing.expect(v.tryPushPacket(one));
    try testing.expect(v.tryPushPacket(two));
    descriptorAt(g, RX_DESC, 0, 0xa000, 128, .{ .write = true }, 0);
    descriptorAt(g, RX_DESC, 1, 0xa080, 128, .{ .write = true }, 0);
    postHead(g, RX_AVAIL, 0, 0, 1);
    postHead(g, RX_AVAIL, 1, 1, 2);
    var visit = v.beginService(g).?;
    v.serviceRxBounded(g, &visit);
    try testing.expectEqualSlices(u8, one, ram[0xa000..][0..one.len]);
    try testing.expectEqualSlices(u8, two, ram[0xa080..][0..two.len]);
    try testing.expectEqual(@as(u16, 2), visit.rx_completions);
    try testing.expectEqual(@as(u64, 2), v.packets_in);
    v.serviceRxBounded(g, &visit);
    try testing.expectEqual(@as(u16, 2), visit.rx_completions);
    try testing.expect(v.validateService(g, &visit));
}
