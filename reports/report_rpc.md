# report_rpc.md - RPC Subsystem Performance & Structural Analysis

An analysis of the RPC subsystem (`src/rpc/`) of the Zephyria codebase, focusing on high-concurrency architecture, memory layouts, allocation limits, and optimizations targeting 1 million TPS.

---

## 1. Subsystem Overview & Code Review

The RPC layer implements several interface options:
* **JSON-RPC 2.0 over HTTP**: Built using a custom TCP server (`http_server.zig`) and dynamic routing (`methods.zig`).
* **gRPC Server**: A basic protobuf-based gRPC transport (`grpc.zig`).
* **WebSocket Server**: Supporting subscription patterns like `eth_subscribe` for real-time events (`websocket.zig`).
* **Introspection Namespace**: Specialized `forge_*` methods providing diagnostics for the DAG mempool, state trie, parallel execution, and VM.
* **Security & Auth**: JWT HMAC-SHA256 signature verification (`security.zig`) for engine API endpoints.

---

## 2. Major Performance Bottlenecks & Design Flaws

### 2.1. Thread-per-Connection OS Thread Spawning
* **Location**: [http_server.zig](file:///Users/karan/sol2zig/src/rpc/http_server.zig) (`serveLoop` / `handleConnection`)
* **Mechanism**: When a client connects, the server spawns a detached OS thread:
  ```zig
  const thread = try std.Thread.spawn(.{}, handleConnection, .{ self, client });
  thread.detach();
  ```
* **Performance Impact**: Spawning a full kernel-managed thread for each connection or request introduces severe context-switching overhead, kernel scheduling latency, and high stack-memory footprint (typically 8MB per thread by default on macOS/Linux). Under high concurrency (e.g., thousands of RPC requests/second), this will lead to file-descriptor exhaustion, thread creation failures (`OutOfMemory` or `ResourceTemporarilyUnavailable`), and CPU cache thrashing.

### 2.2. Global Mutex Contention in Rate Limiting
* **Location**: [http_server.zig](file:///Users/karan/sol2zig/src/rpc/http_server.zig)
* **Mechanism**: IP-based rate limiting is protected by a single global mutex:
  ```zig
  self.rateLimitMutex.lock();
  defer self.rateLimitMutex.unlock();
  ```
* **Performance Impact**: Because every connection thread must acquire this single lock to check or update its request count, the entire multi-threaded RPC server is serialized on this lock. Under high-load validation tests, CPU cores will spend the majority of their cycles spinning on this mutex, completely negating the benefits of parallel processing.

### 2.3. Extensive Heap Allocations during JSON-RPC Serialization
* **Location**: [methods.zig](file:///Users/karan/sol2zig/src/rpc/methods.zig) (e.g., `formatTransaction`, `ethGetLogs`, `ethGetTransactionReceipt`)
* **Mechanism**: To return transaction details, receipts, or logs, the codebase constructs JSON objects using `std.json.ObjectMap.init(allocator)` and formats primitives to hex strings via `std.fmt.allocPrint(allocator, "0x{x}", ...)`:
  ```zig
  try map.put("transactionIndex", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{location.txIndex}) });
  try map.put("blockHash", std.json.Value{ .string = try hex.encode(allocator, &location.blockHash.bytes) });
  ```
* **Performance Impact**: Generating thousands of hex strings and JSON object maps per RPC request triggers hundreds of thousands of heap allocations and frees per second. This triggers allocator fragmentation, CPU cache eviction (due to allocating non-contiguous memory), and GC/allocator latency, making low-microsecond tail latencies impossible.

### 2.4. Linear-Time O(N) Array Operations in WebSockets
* **Location**: [websocket.zig](file:///Users/karan/sol2zig/src/rpc/websocket.zig) (`removeSubscription`)
* **Mechanism**: Subscriptions are maintained in a dynamic array list. Removing a subscription uses `orderedRemove`:
  ```zig
  pub fn removeSubscription(self: *Self, sub_id: u64) bool {
      for (self.subscriptions.items, 0..) |sub, i| {
          if (sub.id == sub_id) {
              _ = self.subscriptions.orderedRemove(i);
              return true;
          }
      }
      return false;
  }
  ```
* **Performance Impact**: `orderedRemove` shifts all elements after the removed item. While the number of subscriptions per socket is usually modest, this represents an inefficient O(N) operation with memory copying on the connection thread.

---

## 3. High-Performance / Mechanical Sympathy Restructuring Plan

### 3.1. Thread-per-Core Event Loop (Kernel Bypass / Non-blocking I/O)
* **Strategy**: Replace the thread-per-connection model with a fixed thread pool (one pinned thread per physical CPU core).
* **Implementation**:
  * Utilize an asynchronous event loop driven by `io_uring` on Linux or `kqueue` on macOS.
  * Share a single socket using `SO_REUSEPORT` across all worker threads, allowing the OS to load-balance incoming connections to the worker event loops without a single listener bottleneck.
  * All sockets are configured as non-blocking (`O_NONBLOCK`). Worker threads pull batches of ready events using `kevent` or `io_uring_peek_batch_cqe`.

### 3.2. Lock-free Shared Rate Limiter
* **Strategy**: Replace the global mutex-protected rate limiter with a lock-free design using atomic operations.
* **Implementation**:
  * Use a lock-free hash table or a sharded hash map (e.g., 64 or 256 shards, each with its own local lock/atomic state) indexed by the IP address hash.
  * Update client rate counters using atomic fetch-add operations (`@atomicRmw`). If a client's request counter exceeds the threshold, drop the connection early without allocating or routing the JSON-RPC request.

### 3.3. Zero-Allocation JSON-RPC Serialization
* **Strategy**: Eliminate heap allocations during RPC query handling by using pre-allocated buffers and direct streaming.
* **Implementation**:
  * **Static Pre-Formatting**: Frequently queried fields (like block headers or transactions) can be pre-serialized to JSON bytes and cached in memory immediately when the block is execution-validated. Serving `eth_getBlockByNumber` then becomes a simple `send` of the cached JSON byte slice (zero-copy from RAM).
  * **Thread-Local Arena or Fixed Buffer Allocators**: For dynamic payloads, use a thread-local `FixedBufferAllocator` backed by a reusable stack-allocated array (e.g., 64KB). The allocator is reset at the end of the connection's event cycle.
  * **Direct Streaming JSON Writer**: Instead of building a complex in-memory AST via `std.json.ObjectMap` and then serializing it, stream the output bytes directly to the socket output buffer using `std.json.stringify` combined with a custom zero-allocation stream writer.
  * **Pre-allocated Hex Buffers**: Avoid `std.fmt.allocPrint` for hex numbers. Format hex values directly into pre-allocated buffers (e.g., `[66]u8`) on the stack.

### 3.4. O(1) Subscription Management
* **Strategy**: Optimize WebSocket subscription insertion and deletion.
* **Implementation**:
  * Instead of an `ArrayList` for subscriptions, use a flat fixed-size array or a fast pointer-based doubly-linked list.
  * Alternatively, swap elements with the last element (`swapRemove`) to make removals O(1) if subscription ordering is not required.
