# Gym NNN — Title

One sentence describing the Candidate's outcome.

## Task

Describe what the Candidate receives, what it must decide or produce, and where
the Work Product belongs on the Trial Case.

## Scoring

Describe the hard gates and weighted criteria. State what is intentionally not
scored.

## Target

Describe the target services, local datasets or assets, and required variables
in the root `.env`. Include any manual setup that must happen before
`just apply NNN`.

## Agent access

List the Candidate's allowed actions or integrations, the Judge's allowed
actions, and the important access boundaries.

## Run

Run from the repository root:

```bash
just tracecat-up
just init NNN
just up NNN
just plan NNN
just apply NNN
just run NNN
just status NNN RUN_ID=<evaluation-run-id>
just judge NNN RUN_ID=<evaluation-run-id>
just export NNN RUN_ID=<evaluation-run-id>
```
