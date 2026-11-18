# Financial Transaction Monitoring and Compliance

A simple rules-based engine that screens financial transactions for suspicious
activity (AML-style checks), stores alerts in SQLite, and produces a CSV
compliance report. Pure Python 3.8+, no external dependencies.

## Files
| File | Purpose |
|---|---|
| `monitor.py` | Rules engine, risk scoring, storage and report |
| `sample_transactions.csv` | Sample input data |
| `test_monitor.py` | Unit tests for each rule |

## Run
```bash
python monitor.py sample_transactions.csv
python -m unittest test_monitor.py -v
```
Outputs `alerts.db` (SQLite table `alerts`) and `alerts_report.csv`.

## Input format
`txn_id,timestamp,account_id,counterparty,country,amount,currency,type`
(timestamps in ISO format, e.g. `2026-11-18T09:00:00`).

## Rules
| Rule | Triggers when | Weight |
|---|---|---|
| LARGE_AMOUNT | amount >= 10,000 | 30 |
| STRUCTURING | 3+ transactions between 8,000 and 10,000 on one account within 24h, totalling >= 10,000 | 50 |
| VELOCITY | more than 5 transactions on one account within 1 hour | 40 |
| HIGH_RISK_COUNTRY | country is in the high-risk list | 35 |
| WATCHLIST_MATCH | counterparty is on the watchlist | 80 |

A transaction's scores add up: 30+ MEDIUM, 50+ HIGH, 80+ CRITICAL.
All thresholds, country codes and the watchlist are constants at the top of `monitor.py`.

## Ideas to extend
- Load the watchlist from a file or API; add fuzzy name matching
- Per-customer behaviour baselines (flag unusual amounts for that customer)
- A small Flask/Streamlit dashboard for analysts to review and close alerts
- Suspicious Activity Report (SAR) export
