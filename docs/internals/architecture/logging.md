# Logging

|                  |                               |
| ---------------- | ----------------------------- |
| Module           | `rvzr/logs.py`                |
| Public interface | `FuzzLogger`, etc.            |
| Inputs           | N/A                           |
| Outputs          | Log messages (stdout, stderr) |

Revizor uses a centralized logging system with configurable verbosity. The system uses the Borg pattern to share state across modules.

Available logging modes:

- info — General messages and progress
- stat — Statistics
- dbg_* — Debug modes for specific components

Logging components:

- Basic functions: `error()`, `warning()`, `inform()`, `dbg()`
- Module-specific loggers: `FuzzLogger`, `GeneratorLogger`, `ISALogger`, `ExecutorLogger`, `AnalyserLogger`

