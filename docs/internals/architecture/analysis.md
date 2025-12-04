|                  |                    |
| ---------------- | ------------------ |
| Module           | `rvzr/analyser.py` |
| Public interface | `Analyser`         |
| Inputs           | `CTrace`, `HTrace` |
| Outputs          | `Violation`        |

The Analyser compares contract traces with hardware traces to detect violations. The core principle: inputs with identical CTraces should produce equivalent HTraces. When they don't, a contract violation has occurred.

```python
For all inputs i, j:
    if CTrace(i) == CTrace(j) and HTrace(i) != HTrace(j):
        → Violation detected
```

Analyser implementations:

Different analysers define "equivalent HTrace" differently:

- `MergedBitmapAnalyser` (default) — Merges samples using bitwise OR, compares bitmaps. For cache-based channels.
- `SetAnalyser` — Compares sets of unique samples.
- `MWUAnalyser` — Uses Mann-Whitney U statistical test. For timing-based channels.
- `ChiSquaredAnalyser` — Uses chi-squared test for distribution differences.
