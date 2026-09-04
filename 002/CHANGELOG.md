# Gym 002 BOTSv3 — CHANGELOG

## 2026-09-04 — Port to Gym 002

- Moved the BOTSv3 lab from the Automations repository into `gyms/002`.
- Replaced remote hourly evidence with the supplied canonical ZIP streamed into
  the local Compose MinIO service through a read-only bind mount.
- Replaced Parquet queries with exact-object gzip JSONL queries through DuckDB.
- Preserved the 34-case queue, hidden evaluation tables, skills, URLscan
  behavior, verdict rules, and evaluator contracts.
- Made readiness fail closed when provider credentials or an organization-default
  model are absent, so `just up` cannot report a partially configured demo.

Decision log behind [`README.md`](README.md) — BOTSv3-derived log lake + seedable alert queue for a
"build a Tier-1 analyst from scratch" demo. Newest first.

> Design intent, generated-data assumptions, and the analyst/builder ground-truth boundary live in
> `README.md` per the labs documentation requirements; this log records dated design decisions,
> tradeoffs, and rejected directions as they happen.

## Open threads / next steps
- Build live evals that grade analyst answers against the hidden `botsv3_alert_outcomes` key.
- Capture a known-good end-to-end closure transcript (one breach case, one false positive) as the
  demo's reference target.
- `event_ref` is a DuckDB `hash(...)` of source fields; DuckDB's `hash()` is **not guaranteed stable
  across major versions**. If analyst-payload `event_ref`s must remain stable across regenerated
  datasets, pin the DuckDB version used by the generator, or
  switch to an explicit stable hash. Not currently a problem (single builder), but note before
  regenerating with a different DuckDB.

## 2026-07-02 — SECURITY (HIGH): analyst ground-truth leak in the alert payload — closed + guarded
**Issue:** The analyst-facing sigma alert payload (built by `base_payload`) carried a
`false_positive` field sourced from `AlertSpec.false_positive_reason`. That field was populated for
**exactly the 6 false-positive alerts** and empty for every true positive — so its *presence alone*
told the analyst which alerts were false positives, before any investigation. This is the lab's
cardinal sin: the analyst is supposed to *earn* the verdict from evidence. It violated the stated
analyst/builder boundary (`README.md`: "ground truth only in hidden evaluator tables") and made the
`sigma_low_signal_requires_correlation` / `vpn_noise_false_positive_path` evals unwinnable-by-design.
The text also contained the out-of-fiction tell "…in this lab." **Live blast radius: none** — the
`botsv3_alerts` table was unseeded, so the leak never reached a running analyst; the fix is entirely
pre-seeding.

**Fix:** Removed the field from every analyst payload; the builder reason now lives only in a hidden
`false_positive_reason` column on `botsv3_alert_outcomes` (evaluator-only). Regenerated `data/*.csv`.

**Root cause:**
1. **One dataclass, two audiences, no wall.** `AlertSpec` holds analyst-visible fields
   (`alert_type`, `severity`, `rule_title`, `notes`) and hidden ground truth (`outcome`,
   `expected_verdict`, `false_positive_reason`) in one flat struct. `base_payload` could reach any
   field; nothing structural stopped it grabbing a verdict field.
2. **A structural (not textual) leak — the sneaky kind.** The tell was the field's *correlation with
   the outcome* (non-empty ⇔ false positive), not any single suspicious value. Each value reads as
   an innocent note in isolation, so eyeballing rows doesn't reveal it.
3. **The boundary was prose, not a test.** The analyst/builder wall was documented in `README.md`
   but nothing enforced it, so a one-line addition to the payload builder could (and did) breach it
   silently.

**Prevention (correctness by construction):** The analyst payload is now built from an analyst-only
projection, so the leak is **structurally impossible** rather than merely detected:
- Added a frozen `PublicAlert` dataclass carrying analyst-visible fields ONLY (no `outcome` /
  `breach_related` / `expected_verdict` / `related_question_ids` / `false_positive_reason`) and an
  `AlertSpec.public()` allowlist projection. `base_payload` and its payload helpers now consume
  `PublicAlert`, so referencing a verdict field there is a build-time `AttributeError`, not silent
  data. The allowlist **fails closed** (a new field is invisible to the analyst until deliberately
  added to `PublicAlert`), the inverse of a denylist that fails open. `notes` remains the one shared
  field (the neutral gd/defender `description`).
- Regeneration is byte-identical — only *how* the payload is constructed changed, not its content.
**Rejected (was the interim wrong-form fix):** the first pass added a **denylist guard** in
`validate_rows` (`GROUND_TRUTH_LEAK_KEYS` — scan the payload for known-bad field names + "in this
lab"). Removed it: a denylist rots as new hidden fields are added, only catches anticipated leak
shapes, and gives false confidence. The structural projection above supersedes it. (Generic lesson
captured in root `LEARNINGS.md` 2026-07-02: correctness by construction over defensive checks.)

## 2026-07-02 — Review pass: dedupe skills, add the analyst source copy, frontmatter
**Decision (dup skills — M5):** Deleted the orphaned, undocumented `skills/botsv3-ir/aws-irp-skills/`
tree — byte-identical to upstream and referenced by nothing (`botsv3-ir/SKILL.md` routes to
`../aws-irp-*`). The canonical copies remain as each `aws-irp-*/REFERENCE.md`.
**Decision (analyst source copy — M4):** Added [`ANALYST_INSTRUCTIONS.md`](ANALYST_INSTRUCTIONS.md),
the repo source copy of the live `soc-t1-analyst` preset (previously only the seeder runbook lived
here). Documented the seeder-vs-analyst file split in `README.md`, and reconciled the "VirusTotal not
wired" rule across `PROMPT.md` and `skills/botsv3-ir/SKILL.md` (VT is skipped, not usable) so the
`urlscan_or_virustotal` evals stay coherent.
**Learning:** Added Agent-Skills YAML frontmatter (`name`/`description`) to all 7 lab `SKILL.md` files
(the upstream wrappers had dropped it). Also fixed the wiz "known CVEs" alert emitting an empty
`vulnerability.id` — it now surfaces the vulnerability by `name` (the indicators are host/file terms,
not CVE numbers; no CVE fabricated).

## 2026-06-29 — Collapse to one clean, generic T1 demo
**Decision:** Make this a single "build a Tier-1 analyst from scratch" lab. Dropped the standing
preset agents (`botsv3-t1-analyst` analyst + `botsv3-case-seeder` seeder were deleted from the
workspace). `PROMPT.md` is now a **data-agnostic meta-prompt** for standing up a generic T1 analyst
(knows only the exact gzip JSONL object URL and DuckDB access — no scenario knowledge or answer
key). `INSTRUCTIONS.md` is now the
**local case-seeder runbook** (run with Tracecat MCP + Claude Code, supports `reset workspace`),
replacing the old analyst instructions; `SEEDER_INSTRUCTIONS.md` was folded into it and removed.
Renamed the directory `botsv3_analyst_demo` → `botsv3`. Merged out and deleted the overlapping
earlier shared preset (its full-lifecycle DuckDB + urlscan model now lives in the meta-prompt).
Kept all data artifacts (alert/answer/outcome CSVs, generator, `skills/`, `evals.json`).
**Tradeoff:** No deployed preset means the demo is recreated each run via MCP + the meta-prompt; that
is the point (it shows how fast a new T1 agent stands up), at the cost of a standing always-on agent.
**Rejected:** Keeping `soc_t1_analyst` as a separate deployed preset — it duplicated this lab's
analyst and split the story across two dirs.
**Learning:** The dataset keeps the `botsv3` name (it *is* BOTSv3 evidence); only the agent built
from the meta-prompt is generic and BOTSv3-unaware. Keep that split — the agent earns the scenario
from evidence, not from its prompt.
