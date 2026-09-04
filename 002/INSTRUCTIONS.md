# Gym 002 operator instructions

Run the gym with `just up`; use `just status`, `just reconcile`, `just down`, and `just reset CONFIRM=002` for lifecycle operations. The project name is `tracecat-gym-002` and its only host listener is `127.0.0.1:28080`.

Reconciliation creates the 34 cases from `data/alerts.csv` once. Analyst-visible payloads contain alert metadata, parsed `alert`, and an exact `event_object_url`. They do not contain the answer, expected verdict, breach-related outcome, evidence filters, or evaluator notes from the hidden CSV files.

```sql
select try_cast(_time as timestamp) as event_time, _sourcetype, source, host
from read_json_auto('http://minio:9000/botsv3/botsv3_2018-08-20_09.jsonl.gz', format = 'newline_delimited');
```

The MinIO policy permits anonymous object reads but not listing or writes. The ZIP is mounted read-only into `dataset-seed`; it is not copied into any image.
