# Outstanding screenshot captures

Seven captures exist and are referenced by [`../../README.md`](../../README.md):

| File | Shows |
| --- | --- |
| `01-entities-table.png` | Cross-case `entities` table, unique index on `entity_ref` |
| `02-entity-observations-table.png` | `entity_observations` with context, `reviewed`, embedding |
| `03-memories-table.png` | `memories` with `summary`, `content`, `memory_ref`, embedding |
| `04-case-linked-entities.png` | Case detail, decision tags, escalation, linked `entities` |
| `05-case-linked-observations-and-memory.png` | Same case, linked observations and memory |
| `06-memory-write-review-required.png` | Inbox, `investigate_case` session pending review |
| `07-memory-write-approval.png` | `core.cases.insert_row` approval with full arguments |

Those cover the *stores* and the *approval*. They do not show the mechanism that
produces them. The captures below close that gap; each maps to a claim the README
currently makes in prose only. Capture in dark mode at a consistent viewport.

## High value — the README argues these without an image

### `08-investigate-case-workflow.png`
**Capture:** Workflows → `Investigate Case`, full graph framed, zoomed so the
recall branch, the `investigate_case` node, and both write-back branches are all
visible.
**Why:** The architecture Mermaid diagram in the README is hand-drawn. One frame
of the real graph proves recall, investigation, extraction, and memory production
are a single managed workflow rather than four scripts.

### `09-semantic-recall-branch.png`
**Capture:** Same workflow, zoomed to `format_case` → `embed_query` →
`list_memories` / `search_entity_observations` → `filter_reviewed_observations` →
`rank_memories` / `rank_observations`.
**Why:** This is the recall path the whole gym turns on, and it makes the
`format_case` leftover visible — the README claims it can be reduced to a plain
case read, and the graph is where a reader checks that.

### `10-embed-query-action.png`
**Capture:** `embed_query` action panel, showing the OpenRouter URL,
`voyageai/voyage-4-lite`, `dimensions: 1024`, the
`SECRETS.openrouter.OPENROUTER_API_KEY` header, and the input template limited to
case ID, summary, description, and payload.
**Why:** Two README claims land here at once — embeddings are a plain HTTP call
because there is no model-catalog path for them, and the query is deliberately
scoped to a small slice of the case. Also the reference for "change `dimensions`
on every embedding step together."

### `11-filter-reviewed-observations.png`
**Capture:** `filter_reviewed_observations` action panel with the
`python_lambda` fully visible.
**Why:** The README states this step does not actually filter on review state.
The lambda `... and (row["reviewed"] or True)` is the evidence, and it is the
single most important caveat in the current implementation.

### `12-rank-observations-script.png`
**Capture:** `rank_observations` action panel with the numpy script and its inputs
(`limit: 10`, `embedding_column`, `raw_query_vector`), scrolled so the `min_score`
parameter and the score in the returned shape are both on screen.
**Why:** Backs "top 10, no score floor, score returned so the agent can decide,
`min_score` available if you want a floor."

### `13-investigate-case-prompt.png`
**Capture:** `investigate_case` action panel, `user_prompt` expanded, showing the
`<memory-context>` and `<entity-observations>` blocks with their system notes, the
`FN.to_markdown_table(...)` rendering, and the close-if-medium-or-below /
assign-if-above instruction.
**Why:** This is where memory actually reaches the model, and where the README's
"nothing stops the agent from closing instead of escalating except the prompt"
claim is verifiable. The strongest single argument for just-in-time tool approval.

### `14-save-memory-action.png`
**Capture:** `save_memory` action panel showing `actions: ["core.cases.insert_row"]`,
the same `preset`, no `session_id` override, and the prompt's "skip rather than
saving a memory saying there's nothing to save" instruction plus the
`# Previous memories` block.
**Why:** Pairs directly with `07-memory-write-approval.png` — that screenshot shows
the gate firing, this one shows the action override that makes the gate narrow
enough to be worth having.

## Useful — supporting detail

### `15-entity-extraction-branch.png`
**Capture:** Workflow zoomed to `format_updated_case` → `extract_entities` →
`scatter_entities` → `insert_entity` / `embed_entity_observation` →
`insert_entity_observation` → `link_entity` / `link_observation`.
**Why:** Shows that entity and observation writes are deterministic workflow
steps, which is the README's stated reason there is no agent tool approval on them.

### `16-insert-entity-observation-upsert.png`
**Capture:** `insert_entity_observation` action panel showing `upsert: true`, the
`observation_ref` template, and `reviewed: false`.
**Why:** Ties the unique index in `02-entity-observations-table.png` to the
mechanism that uses it, and shows `reviewed` is hardcoded false at insert.

### `17-extract-entities-prompt.png`
**Capture:** `extract_entities` action panel, instructions scrolled to the entity
type enum and the "do not invent types" / "a mistyped entity is worse than a
nonexistent one" hints, plus the `user_prompt` with the previously-extracted
entity list.
**Why:** Supports "types are OCSF-derived but not strictly, and not enforced" and
"extraction avoids re-extracting."

### `18-entities-table-index-config.png`
**Capture:** Tables → `entities` → the index configuration for `entity_ref`
(and the same for `observation_ref` on `entity_observations`).
**Why:** The upsert dedup story currently rests on a badge in the corner of
`01-entities-table.png`. This makes it explicit.

### `19-openrouter-workspace-secret.png`
**Capture:** Workspace secrets list showing the `openrouter` secret, key name only.
**Why:** Completes the "resolved from a workspace secret, not a configured
provider" claim. Do not reveal the value.

### `20-case-agent-runs.png`
**Capture:** Case detail → **View agent runs**, showing the `investigate_case`
session with the case as its linked entity, and the separate `extract_entities`
session with none.
**Why:** Backs two claims that are otherwise invisible — the investigation session
maps to the user and links the case, and entity extraction deliberately runs in a
new unlinked session.

### `21-case-embeddings-table.png`
**Capture:** Tables → `case_embeddings`, showing `case_id` and `embedding` rows.
**Why:** The README notes this table is written but never read back. Showing it
populated makes the forward-looking case-to-case similarity point concrete rather
than theoretical.
