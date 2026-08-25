# B20 API Honesty Gaps — Design Spec

**Date:** 2026-08-25  
**Status:** Approved — awaiting implementation  
**Covers:** Gaps 1 (score:null), 2 (origin diagnostic), 3 (version wiring) + frontend companion

---

## Background

Three honesty gaps verified on live @grok and @grok-adjacent B20 scans. All three
let a consumer read a field and draw a wrong conclusion from it. The priority order
matches impact: Gap 1 is a false-safe at the integration layer (the #34/#35 pattern
reborn), Gaps 2–3 are diagnostic/labelling gaps.

---

## Gap 1 — `score: null` for unrated dimensions (HIGH)

### Decision

`DimensionResult.to_dict()` returns `score: null` (Python `None`) when the dimension
is unrated, and the real `float` when rated. Additionally, `"rated": bool` is always
included in the serialized output.

**Why null, not `rated:false` with a 100 score:**  
A score of 100 for an unrated dimension is the false-safe pattern — absence shown as a
good-looking default, with a separate flag you must read to know it's a lie. null
forces honesty at the consumer: `null * weight` fails loud instead of silently
computing 99 against a trust_score of 20. Belt-and-suspenders: null forces correctness,
`rated:false` aids readability.

**Backward compat:** The `unrated_dimensions` array is preserved. Consumers that already
filter on it continue to work; new consumers use `rated` per dimension.

### Wire shape change

Before (current):
```json
"dimensions": {
  "issuer_authority": { "score": 100.0, "weight": 0.30, "findings": [] }
}
```

After:
```json
"dimensions": {
  "issuer_authority": { "score": null, "rated": false, "weight": 0.30, "findings": [] }
}
```

Rated dimension (unchanged score, added `rated`):
```json
"supply_integrity": { "score": 85.0, "rated": true, "weight": 0.25, "findings": [...] }
```

### Implementation touch-points

- `acpsec_api/b20/models.py` — `DimensionResult.to_dict()`: include `"rated": self.rated`;
  return `None` for `score` when `not self.rated`.
- `acpsec_api/b20/__init__.py` — version bump (see Gap 3; this contract change demands it).
- No engine arithmetic changes: `_raw_sum()` already guards via `if d.rated`.

---

## Gap 2 — Incomplete `read_diagnostics` coverage (MEDIUM)

### Problem

`origin_transparency` requires both `issuer_has_history` and `announcement_events`.
When only `issuer_has_history` is None (tx-count read failed but announcement log
succeeded), the dimension is unrated with no diagnostic entry — the reader never emits
a `"tx_count"` key, and `_READ_SOURCE_DIMENSIONS` has no mapping for it.

The live symptom: `origin_transparency` appears in `unrated_dimensions`, has a Low
finding and score 90 (from known `announcement_events=False`), but `read_diagnostics`
has no entry for it.

### Two-layer fix

**Layer A (reader)** — `acpsec_api/b20/reader.py`, `read_origin()`:  
Emit `read_diagnostics["tx_count"] = "tx-count read returned None (RPC error or no issuer address)"` when `issuer_has_history` is None after the tx-count attempt.

**Layer A (engine mapping)** — `acpsec_api/b20/engine.py`, `_READ_SOURCE_DIMENSIONS`:  
Add `"tx_count": ("origin_transparency",)` so the engine maps the tx_count diagnostic
to its affected dimension.

**Layer B (engine fallback)** — `read_diagnostics_for()`:  
After the source-map pass, for any dimension in `unrated` that still has no entry, add
a synthetic fallback: `"unrated: no read diagnostic recorded"`. This is the safety net
that prevents future gaps when new dimensions or read paths are added without updating
the source map.

### Invariant

**Every unrated dimension must have a `read_diagnostics` entry.** The layer-B fallback
enforces this as a post-condition of `read_diagnostics_for()`.

---

## Gap 3 — `scanner_version` stuck at "0.1.0" (LOW)

### Decision

Wire `__version__` in `acpsec_api/b20/__init__.py` to `importlib.metadata` at import
time, with a `"dev"` fallback for editable installs without metadata. Bump
`pyproject.toml` to `0.6.0` (null-able score is a contract change).

```python
from importlib.metadata import PackageNotFoundError, version as _pkg_version
try:
    __version__ = _pkg_version("acpsec")
except PackageNotFoundError:
    __version__ = "dev"
```

Going forward: bumping `pyproject.toml` is the only required action to update
`scanner_version`. No separate `__init__.py` edit.

The one test asserting `scanner_version == "0.1.0"` (`test_engine_assess.py:56`) is
updated to assert against `importlib.metadata.version("acpsec")` so it tracks
automatically too.

---

## Frontend companion — null-tolerance in `DimensionBreakdown` (deploy BEFORE backend)

### Rule: consumer before producer

The frontend null-tolerance change must be live on `acpsec.app` **before** the backend
null change is deployed to Railway. Deploying null from the backend first would cause
the existing `dim.score/100` string interpolation to render `"null/100"` and the
`Math.max(0, Math.min(100, null))` in the progress bar style to silently produce `0%`
via null-to-0 coercion.

### Vulnerabilities in `DimensionBreakdown.tsx`

Current code derives `isUnrated` from `result.unrated_dimensions` (a Set lookup). With
the new backend shape, each `B20Dimension` carries its own `rated` field — the per-dim
flag is more reliable than the array when both are available.

Three locations need hardening:

1. **Score display** (`{isUnrated ? "—" : `${dim.score}/100`}`)  
   Must not render `null/100`. Guard: prefer `dim.rated === false` OR `dim.score == null`.

2. **Progress bar `style`** (`Math.max(0, Math.min(100, dim.score))%`)  
   `Math.min(100, null)` coerces to 0 silently — not a crash, but an implicit
   dependency on null→0 coercion. Explicit guard: `dim.score ?? 0`.

3. **`aria-valuenow`** (`aria-valuenow={dim.score}`)  
   `null` renders as an absent attribute (fine). Explicit guard: `dim.score ?? undefined`.

### Type changes

`B20Dimension` in `src/lib/api/types.ts`:
```typescript
export type B20Dimension = {
  score: number | null;   // null when unrated (new backend shape)
  rated?: boolean;        // false when unrated; absent on old responses → treat as true
  weight: number;
  findings: B20Finding[];
};
```

### Updated `isUnrated` derivation

Prefer `dim.rated === false`; fall back to `unrated_dimensions` set for old-shape
responses where `rated` is absent:

```typescript
const isUnrated = dim.rated === false || unrated.has(key);
```

This is backward-compatible: old responses have no `rated` field (undefined ≠ false),
so the set-lookup fallback fires.

---

## Deployment order

1. **Frontend** — ship null-tolerant `DimensionBreakdown` + updated `B20Dimension` type
2. **Backend** — ship Gap 1 (score:null) + Gap 2 (diagnostics) + Gap 3 (version bump)
   together in one PR (they are additive, all safe to ship together)

---

## Test plan (TDD)

### Backend RED tests to write (before any production code)

| Test | File | What it proves |
|------|------|----------------|
| Unrated dim → `score: null, rated: false` in `to_dict()` | `test_models.py` | serialization shape |
| Rated dim → `score: float, rated: true` in `to_dict()` | `test_models.py` | not broken for happy path |
| `assess()` unrated dim shows null score in output | `test_engine_assess.py` | end-to-end |
| Every unrated dim has a `read_diagnostics` entry | `test_engine_composite.py` | layer-B invariant |
| Origin unrated (tx_count None, announcement known) has diagnostic | `test_engine_composite.py` | layer-A specific |
| `scanner_version` equals `importlib.metadata.version("acpsec")` | `test_engine_assess.py` | version wiring |

### Frontend RED tests to write (before DimensionBreakdown changes)

| Test | File | What it proves |
|------|------|----------------|
| Null score → "—" (using `dim.rated`, not list alone) | `DimensionBreakdown.test.tsx` | consumer-before-producer guard |
| Progress bar `aria-valuenow` absent/zero for null score | `DimensionBreakdown.test.tsx` | no silent coercion |
