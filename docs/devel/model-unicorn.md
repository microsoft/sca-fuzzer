# Unicorn Backend

Unicorn backend architecture:

```text
UnicornModel (main orchestrator)
  ├─ UnicornTracer            Records observations (PC, memory addresses, etc.)
  ├─ UnicornSpeculator        Simulates speculative execution
  ├─ UnicornTaintTracker      Tracks data flow for boosted input generation
  ├─ ExtraInterpreter         Handles features Unicorn doesn't support
  └─ InstructionCoverage      Tracks which instructions were tested
```

Key components:

- `UnicornModel`:   Manages the emulator and coordinates components through hooks on instruction and memory events.
- `UnicornTracer`:   Implements the observation clause of the contract. Different tracers record different information (program counters, memory addresses, data values).
- `UnicornSpeculator`:   Implements the speculation clause using checkpoint-rollback mechanisms. When speculation triggers (branch misprediction, CPU exception), it saves state and executes speculatively up to a window limit (default 250 instructions). It rolls back on serializing instructions or window expiration.
- `UnicornTaintTracker`:   Performs dynamic taint analysis to identify which input bytes affect the contract trace. Used for boosted input generation.

