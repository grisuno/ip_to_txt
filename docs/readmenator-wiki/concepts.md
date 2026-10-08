# Concepts

Second-brain semantic layer: nouns map atomically to file sets (EXTRACTED); verbs aggregate structural edges (INFERRED).

| Concept | Files | Mentions | Top Files |
|---------|-------|----------|-----------|
| `int` | 3 | 8 | `app.py`, `ip_to_db.py`, `main.go` |
| `ips` | 3 | 4 | `app.py`, `ip_to_db.py`, `main.go` |
| `private` | 3 | 4 | `app.py`, `ip_to_db.py`, `main.go` |
| `domain` | 2 | 5 | `ip_to_db.py`, `main.go` |
| `process` | 2 | 3 | `ip_to_db.py`, `main.go` |
| `save` | 2 | 3 | `ip_to_db.py`, `main.go` |
| `generate` | 2 | 2 | `app.py`, `ip_to_db.py` |

## Dialectic Prompts

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
