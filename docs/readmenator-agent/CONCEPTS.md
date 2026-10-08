# Concepts

Nouns map atomically to file sets (EXTRACTED); verbs aggregate structural edges (INFERRED).

- `int` | files=3 | mentions=8 | `app.py`, `ip_to_db.py`, `main.go`
- `ips` | files=3 | mentions=4 | `app.py`, `ip_to_db.py`, `main.go`
- `private` | files=3 | mentions=4 | `app.py`, `ip_to_db.py`, `main.go`
- `domain` | files=2 | mentions=5 | `ip_to_db.py`, `main.go`
- `process` | files=2 | mentions=3 | `ip_to_db.py`, `main.go`
- `save` | files=2 | mentions=3 | `ip_to_db.py`, `main.go`
- `generate` | files=2 | mentions=2 | `app.py`, `ip_to_db.py`

## Dialectic

- Thesis: `domain` centralizes 2 files; Antithesis: `int` pulls 3 files with 2 shared (Jaccard 0.67); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `domain` centralizes 2 files; Antithesis: `ips` pulls 3 files with 2 shared (Jaccard 0.67); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `domain` centralizes 2 files; Antithesis: `private` pulls 3 files with 2 shared (Jaccard 0.67); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `domain` centralizes 2 files; Antithesis: `process` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `domain` centralizes 2 files; Antithesis: `save` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `generate` centralizes 2 files; Antithesis: `int` pulls 3 files with 2 shared (Jaccard 0.67); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `generate` centralizes 2 files; Antithesis: `ips` pulls 3 files with 2 shared (Jaccard 0.67); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `generate` centralizes 2 files; Antithesis: `private` pulls 3 files with 2 shared (Jaccard 0.67); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `int` centralizes 3 files; Antithesis: `ips` pulls 3 files with 3 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `int` centralizes 3 files; Antithesis: `private` pulls 3 files with 3 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
