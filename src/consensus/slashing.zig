const std = @import("std");
const core = @import("core");
const types = @import("types.zig");

/// Reason for a slash event.
pub const SlashReason = enum(u8) {
    DoubleSigning = 0,
    DoubleAttestation = 1,
    InvalidBlock = 2,
};

/// Evidence of a slashable offense with FULL evidence (both conflicting items).
pub const SlashEvent = struct {
    /// The offending validator's address
    validator: core.types.Address,
    /// Block number where the offense occurred
    blockNumber: u64,
    /// Reason for slashing
    reason: SlashReason,
    /// First conflicting hash (block ID, attestation hash, etc.)
    evidenceHash1: core.types.Hash,
    /// Second conflicting hash (proves equivocation)
    evidenceHash2: core.types.Hash,
    /// Timestamp when detected
    detectedAt: u64,
};

/// Proposal record for double-sign detection.
pub const ProposalRecord = struct {
    blockId: core.types.Hash,
    proposer: core.types.Address,
    timestamp: u64,
};

/// Double-signing detector.
/// Tracks all proposals seen and detects equivocation.
pub const SlashingDetector = struct {
    allocator: std.mem.Allocator,
    proposalsSeen: std.AutoHashMap(u64, ProposalRecord),
    slashEvents: std.ArrayListUnmanaged(SlashEvent),
    pendingBroadcasts: u32,

    pub fn init(allocator: std.mem.Allocator) SlashingDetector {
        return SlashingDetector{
            .allocator = allocator,
            .proposalsSeen = std.AutoHashMap(u64, ProposalRecord).init(allocator),
            .slashEvents = .{},
            .pendingBroadcasts = 0,
        };
    }

    pub fn deinit(self: *SlashingDetector) void {
        self.proposalsSeen.deinit();
        self.slashEvents.deinit(self.allocator);
    }

    /// Record a new proposal. Returns SlashEvent if equivocation detected.
    pub fn recordProposal(
        self: *SlashingDetector,
        blockNumber: u64,
        blockId: core.types.Hash,
        proposer: core.types.Address,
    ) ?SlashEvent {
        const gop = self.proposalsSeen.getOrPut(blockNumber) catch return null;
        if (gop.found_existing) {
            if (!std.mem.eql(u8, &gop.value_ptr.blockId.bytes, &blockId.bytes)) {
                const ev = SlashEvent{
                    .validator = proposer,
                    .blockNumber = blockNumber,
                    .reason = .DoubleSigning,
                    .evidenceHash1 = gop.value_ptr.blockId,
                    .evidenceHash2 = blockId,
                    .detectedAt = @intCast(std.time.timestamp()),
                };
                self.slashEvents.append(self.allocator, ev) catch return null;
                self.pendingBroadcasts += 1;
                return ev;
            }
        } else {
            gop.value_ptr.* = ProposalRecord{
                .blockId = blockId,
                .proposer = proposer,
                .timestamp = @intCast(std.time.timestamp()),
            };
        }
        return null;
    }

    /// Check if a block number already has a proposal (equivocation cross-reference).
    pub fn proposalExists(self: *SlashingDetector, blockNumber: u64) bool {
        return self.proposalsSeen.contains(blockNumber);
    }

    /// Drain all pending slash events.
    pub fn drainEvents(self: *SlashingDetector, allocator: std.mem.Allocator) ![]SlashEvent {
        if (self.slashEvents.items.len == 0) return &[_]SlashEvent{};
        const events = try allocator.alloc(SlashEvent, self.slashEvents.items.len);
        @memcpy(events, self.slashEvents.items);
        self.slashEvents.clearRetainingCapacity();
        self.pendingBroadcasts = 0;
        return events;
    }

    /// Get stats.
    pub fn getStats(self: *const SlashingDetector) struct { totalEvents: usize, pendingBroadcasts: u32 } {
        return .{
            .totalEvents = self.slashEvents.items.len,
            .pendingBroadcasts = self.pendingBroadcasts,
        };
    }
};
