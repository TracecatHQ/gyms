# Gym 003: vulnerability-driven firewall mitigation

Gym 003 is a reproducible, isolated exercise for this lifecycle:

`Nuclei suspicion → Tracecat case → independent verification → analyst proposal → case task → BunkerWeb rule → retest → case evidence`

The fictional service accepts supplier documents, receives independent JSON
order updates, supports staff login, and exposes a health check. n8n 1.65.0 is
reachable only through BunkerWeb. A fixed-target test service runs the reviewed
checks and holds the firewall credential; neither agent receives that credential
or an arbitrary target, command, or rule-writing interface.

## Supply-chain policy

All Compose images use immutable manifest digests. Image metadata comes from the
official publisher or Docker Official Image registry and is recorded in
`gym.lock.json` and `PROVENANCE.md`. An image may be downloaded only after a
seven-day cooldown. The repository's September 3 Tracecat images were already
present on this host; startup refuses to fetch them before their September 10
cooldown date. Python dependencies inherited from Tracecat are exact `==` pins;
Gym 003 adds no floating package requirement.

Run `just verify-supply-chain` to query the recorded official Docker Hub metadata
without pulling images. Review any digest or publication-date change before
updating the lock.

## Demo

From this directory:

```sh
just init
just doctor
just up
just wait
```

Open Tracecat at <http://127.0.0.1:38080>. The protected application ingress is
<http://127.0.0.1:38081> with host name `supplier.intake.test`; n8n itself has no
published port.

Tracecat must have a provider and organization-default model before it can create
the two agent presets. If the initial reconcile reports that no default model is
configured, set one in the Tracecat UI, then run `just reconcile` and `just wait`.

The reconciler creates one CVE-2026-21858 case, two agent presets, three published
workflows, and three independently runnable case tasks:

- `Test exploitability` runs fresh attack and benign verification without a rule change.
- `Create LOG-only rule` installs the same predicate in observation mode, retests, and records correlated events.
- `Create BLOCK rule` snapshots configuration, installs the blocking predicate, confirms activation, retests attack and benign behavior, and rolls back on incomplete verification or regression.

Task comments retain the rule/revision, workflow execution and test run references,
before/after verdicts, benign results, correlated WAF events, MinIO evidence links,
and rollback state. A successful rule is described as mitigation at the tested
ingress; the vulnerable application version remains unchanged and the scanner can
continue to report it.

Run the complete active acceptance sequence explicitly:

```sh
just evaluate
```

It tests baseline, LOG_ONLY, BLOCK, removal/restoration, header casing,
content-type parameters, route normalization, target outage handling, malformed
and stale proposals, duplicate application, and failed reload rollback. This is
the only command intended to exercise the complete fixed exploit chain.

`just check` validates configuration and, when the stack is running, performs
non-destructive health checks. `just down` retains volumes and evidence.

## Reset and retained evidence

The active verifier creates only one temporary workflow and removes it. n8n is
configured not to persist webhook success/error payloads, preventing copied file
data from accumulating in its SQLite database. If cleanup cannot be confirmed,
it marks the scenario dirty and refuses another run.

After capturing artifacts, reset the target and managed firewall state with:

```sh
just scenario-reset CONFIRM=artifacts-captured
```

MinIO and job evidence remain. Full volume deletion uses
`just reset CONFIRM=artifacts-captured`; host-side `eval-results/` is retained.

## Baseline boundary

ModSecurity starts enabled with only the declared Gym 003 baseline configuration.
BunkerWeb bad-behavior bans and request-rate limits are disabled for deterministic
replay, and the reverse proxy forwards the editor methods needed for verified
cleanup.
The agent-visible scenario inventory is in `benchmark/scenario.json`. Expected
evaluation outcomes are kept separately under `benchmark/evals/`.

## Demo walkthrough

Enable dark mode and use a 1600 × 1000 browser window for the same framing as
the reference images.
Before presenting, start and reconcile the gym:

```sh
cd /Users/chris/repos/gyms/003
just up
just wait
just reconcile
just status
just check
```

`just status` must report one case, three tasks, three managed workflows, and two
presets. If Tracecat has no organization default, open
<http://127.0.0.1:38080/organization/settings/agent>, configure OpenAI, select
`gpt-5.6-terra`, and run the commands again. Do not place a key in a terminal,
README, screenshot, or case comment.

### 1. Establish the scanner finding

**Action:** Open <http://127.0.0.1:38080>, select **Cases**, and open
**CASE-0001 — Suspected unauthenticated n8n RCE at supplier.intake.test**.

**Expected state:** The case is Critical/High and says Nuclei found a
CVE-2026-21858 vulnerable-version signal. It also says independent verification
is required before impact is confirmed.

![Gym 003 case and scanner evidence](docs/screenshots/01-case-overview.png)

**Presenter notes:** “The scanner starts the investigation, but the gym treats a
version match as suspicion. The case names the supplier upload surface and the
benign traffic that a mitigation must preserve.”

### 2. Show the two specialist agents

**Action:** Select **Agents** in the workspace navigation.

**Expected state:** Exactly **Gym 003 Attack Surface Verifier** and **Gym 003
Mitigation Analyst** are visible, both using OpenAI `gpt-5.6-terra`. There is no
investigation-wrapper workflow or agent.

![Gym 003 preset agents](docs/screenshots/02-agents.png)

**Presenter notes:** “The Verifier owns a tightly constrained, fixed-target
verification action. The Analyst reads case evidence and writes a proposal; it
has no firewall-write or workflow-execution permission.”

### 3. Verify exploitability from the case

**Action:** Return to CASE-0001, click **Toggle Chat**, start a new case chat,
select **Gym 003 Attack Surface Verifier**, and send this prompt, replacing
`<case_uuid>` with the UUID in the case URL:

```text
Investigate this case for fixed scenario supplier-intake. Run one fresh verification with case_id=<case_uuid>, scenario=supplier-intake, proposal_revision=1, and mode=VERIFY_ONLY. Return the configured structured verdict.
```

**Expected state:** The chat shows one `core.workflow.execute` call and structured
output with `verdict: confirmed_rce`, `benign_compatible: true`, sanitized `s3://`
evidence references, and completed workflow cleanup. The case receives a
sanitized **Gym 003 verification** comment.

![Gym 003 case-scoped verifier result](docs/screenshots/03-verifier-run.png)

**Presenter notes:** “The agent can launch only the fixed verification workflow.
The harmless marker proves impact, raw exploit material is never written to the
case, and the temporary target workflow is removed.”

### 4. Produce a proposal without changing the WAF

**Action:** Start another case chat, select **Gym 003 Mitigation Analyst**, and
send:

```text
Review this case for scenario supplier-intake, including its latest verification evidence and tasks. Produce the configured restricted mitigation proposal and add one sanitized proposal comment to the case. Do not execute a workflow or change the firewall.
```

Then click the case’s **0/3** task control.

**Expected state:** The chat shows only case read/comment tools and a structured
route/content-type proposal. The three human-controlled tasks are **Create BLOCK
rule**, **Create LOG-only rule**, and **Test exploitability**.

![Gym 003 analyst proposal and case tasks](docs/screenshots/04-proposal-and-tasks.png)

**Presenter notes:** “The analyst narrows the policy to the demonstrated route,
method, and normalized media type. It explains compatibility and rollback, then
stops. A person chooses whether to observe, block, or retest.”

### 5. Apply and verify BLOCK

**Action:** In the task list, select **Create BLOCK rule**, click **Gym 003 -
Apply reviewed firewall rule**, choose `BLOCK`, keep the case-populated values,
and click **Trigger**. Wait for the run to complete, then return to the case’s
latest firewall result. For the complete acceptance run, execute:

```sh
just evaluate
```

**Expected state:** A successful BLOCK result records `confirmed_rce` before the
rule, `blocked_by_waf` after it, required benign transactions as passed,
audit-correlated WAF events, no rollback, and `mitigated at tested ingress`.
`just evaluate` writes its JSON result beneath
`eval-results/supplier-intake/acceptance/` and restores the managed WAF state.

![Gym 003 verified BLOCK result](docs/screenshots/05-final-result.png)

**Presenter notes:** “The deterministic workflow holds the WAF credential. It
confirms activation, proves the attack is denied, checks independent JSON,
receipt, login, health, and upload traffic, and retains correlated evidence. The
application is still vulnerable; the claim is mitigation at this ingress.”

### Repeat the demo

After preserving the screenshots and run references, restore the target and WAF
without deleting retained evidence:

```sh
just scenario-reset CONFIRM=artifacts-captured
just reconcile
just status
just check
```

Use `just reset CONFIRM=artifacts-captured` only when you intend to delete the
Gym 003 volumes. Review the case before presenting again and avoid displaying
credentials, cookies, extracted values, raw payloads, or secret-bearing logs.
