# Smux Priority Shaper

The Priority Shaper is an advanced multiplexing optimization for StealthLink that ensures control traffic remains responsive even under heavy data load. It intercepts `smux` frames at the transport layer and re-orders them based on priority and fairness policies.

## Features

- **Protocol-Aware Prioritization**: Automatically identifies `smux` frame types (SYN, FIN, UPD, NOP) and prioritizes them over data frames (PSH).
- **Round-Robin Scheduling**: Ensures fairness between different streams within the same priority class, preventing any single stream from hogging the bandwidth.
- **Starvation Prevention**: Guaranteed bandwidth for data frames. After a configurable burst of control frames, the shaper will interleave data frames even if more control frames are pending.
- **Backpressure Support**: Implements an internal queue with configurable size. When the queue is full, `Write` calls will block, naturally propagating backpressure to the application layer.
- **Robust Re-alignment**: Automatically detects and handles zero-padded or corrupted streams by re-aligning with valid `smux` version headers.

## Configuration

The shaper is configured via the `PriorityShaperConfig` struct within the global StealthLink configuration:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Enabled` | `bool` | `true` | Whether to enable the priority shaper. |
| `MaxControlBurst` | `int` | `16` | Maximum number of consecutive control frames allowed before forced data frame interleaving. |
| `QueueSize` | `int` | `1024` | Maximum number of frames to buffer before applying backpressure. |

## Metrics

The shaper exposes several metrics for monitoring transport health:

- `smux_shaper_control_frames_total`: Total number of control frames processed.
- `smux_shaper_data_frames_total`: Total number of data frames processed.
- `smux_shaper_queue_size`: Current number of frames in the shaper queue.
- `smux_shaper_starvation_preventions_total`: Number of times the starvation prevention logic forced a data frame to be sent.

## Implementation Details

The shaper wraps a `net.Conn` and is typically integrated into the `uqsp.RuntimeSession`. It uses an internal goroutine for the `writeLoop` to decoupled application writes from the underlying transport's actual throughput.

**Endianness Warning**: The shaper uses `LittleEndian` for parsing `smux` headers, matching the observed behavior of the `xtaci/smux` library v1.5.56+ in the StealthLink environment.
