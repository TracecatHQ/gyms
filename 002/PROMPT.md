# BOTSv3 analyst prompt

Triage every case in the Gym 002 queue. Start with the sparse alert payload, then query the case's exact `event_object_url` using `core.duckdb.execute_sql` and DuckDB `read_json_auto`. Derive `event_time` with `try_cast(_time as timestamp)`.

The URL has the internal form `http://minio:9000/botsv3/botsv3_<YYYY-MM-DD>_<HH>.jsonl.gz`.

Do not list the bucket, guess alternate objects, expose full `_raw` events, or use hidden answers/outcomes. Preserve the existing BOTSv3 verdict rules, URLscan enrichment behavior, response lifecycle, case description format, and closure tags described in `ANALYST_INSTRUCTIONS.md`.
