"""
Financial Transaction Monitoring and Compliance
-----------------------------------------------
A simple rules-based engine that screens transactions for suspicious
activity (AML-style checks), stores alerts in SQLite and writes a
compliance report.

Usage:
    python monitor.py sample_transactions.csv
    python monitor.py sample_transactions.csv --db alerts.db --report alerts_report.csv
"""

import argparse
import csv
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

# --------------------------------------------------------------------------
# Configuration (tune these to your compliance policy)
# --------------------------------------------------------------------------
LARGE_AMOUNT_THRESHOLD = 10_000.00      # reporting threshold
STRUCTURING_MIN_RATIO = 0.80            # txns >= 80% of threshold but below it
STRUCTURING_MIN_COUNT = 3               # how many such txns in the window
STRUCTURING_WINDOW = timedelta(hours=24)
VELOCITY_MAX_TXNS = 5                   # more than this in the window = alert
VELOCITY_WINDOW = timedelta(hours=1)

HIGH_RISK_COUNTRIES = {"IR", "KP", "SY", "MM", "AF"}
WATCHLIST = {"SHADOW TRADING LLC", "ACME OFFSHORE LTD", "BLACKROCK HOLDINGS FZE"}

# Risk weights per rule; total score decides severity
RULE_WEIGHTS = {
    "LARGE_AMOUNT": 30,
    "STRUCTURING": 50,
    "VELOCITY": 40,
    "HIGH_RISK_COUNTRY": 35,
    "WATCHLIST_MATCH": 80,
}


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
@dataclass
class Transaction:
    txn_id: str
    timestamp: datetime
    account_id: str
    counterparty: str
    country: str
    amount: float
    currency: str
    txn_type: str


@dataclass
class Alert:
    txn_id: str
    account_id: str
    rule: str
    description: str
    score: int


def load_transactions(path):
    """Read transactions from a CSV file."""
    txns = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            txns.append(
                Transaction(
                    txn_id=row["txn_id"].strip(),
                    timestamp=datetime.fromisoformat(row["timestamp"].strip()),
                    account_id=row["account_id"].strip(),
                    counterparty=row["counterparty"].strip(),
                    country=row["country"].strip().upper(),
                    amount=float(row["amount"]),
                    currency=row["currency"].strip().upper(),
                    txn_type=row["type"].strip().lower(),
                )
            )
    return sorted(txns, key=lambda t: t.timestamp)


# --------------------------------------------------------------------------
# Rules. Each takes the full list of transactions and returns a list of Alerts.
# --------------------------------------------------------------------------
def rule_large_amount(txns):
    return [
        Alert(t.txn_id, t.account_id, "LARGE_AMOUNT",
              f"Amount {t.amount:,.2f} {t.currency} >= threshold {LARGE_AMOUNT_THRESHOLD:,.2f}",
              RULE_WEIGHTS["LARGE_AMOUNT"])
        for t in txns if t.amount >= LARGE_AMOUNT_THRESHOLD
    ]


def rule_high_risk_country(txns):
    return [
        Alert(t.txn_id, t.account_id, "HIGH_RISK_COUNTRY",
              f"Transaction involves high-risk country {t.country}",
              RULE_WEIGHTS["HIGH_RISK_COUNTRY"])
        for t in txns if t.country in HIGH_RISK_COUNTRIES
    ]


def rule_watchlist(txns):
    return [
        Alert(t.txn_id, t.account_id, "WATCHLIST_MATCH",
              f"Counterparty '{t.counterparty}' is on the watchlist",
              RULE_WEIGHTS["WATCHLIST_MATCH"])
        for t in txns if t.counterparty.upper() in WATCHLIST
    ]


def _by_account(txns):
    groups = defaultdict(list)
    for t in txns:
        groups[t.account_id].append(t)
    return groups


def rule_structuring(txns):
    """Several just-below-threshold transactions in a short window (smurfing)."""
    alerts, flagged = [], set()
    low = LARGE_AMOUNT_THRESHOLD * STRUCTURING_MIN_RATIO
    for acct, items in _by_account(txns).items():
        near = [t for t in items if low <= t.amount < LARGE_AMOUNT_THRESHOLD]
        for i, start in enumerate(near):
            window = [t for t in near[i:] if t.timestamp - start.timestamp <= STRUCTURING_WINDOW]
            total = sum(t.amount for t in window)
            if len(window) >= STRUCTURING_MIN_COUNT and total >= LARGE_AMOUNT_THRESHOLD:
                for t in window:
                    if t.txn_id not in flagged:
                        flagged.add(t.txn_id)
                        alerts.append(Alert(
                            t.txn_id, acct, "STRUCTURING",
                            f"{len(window)} transactions just under threshold within 24h "
                            f"(total {total:,.2f})",
                            RULE_WEIGHTS["STRUCTURING"]))
    return alerts


def rule_velocity(txns):
    """Too many transactions from one account in a short window."""
    alerts, flagged = [], set()
    for acct, items in _by_account(txns).items():
        for i, start in enumerate(items):
            window = [t for t in items[i:] if t.timestamp - start.timestamp <= VELOCITY_WINDOW]
            if len(window) > VELOCITY_MAX_TXNS:
                for t in window:
                    if t.txn_id not in flagged:
                        flagged.add(t.txn_id)
                        alerts.append(Alert(
                            t.txn_id, acct, "VELOCITY",
                            f"{len(window)} transactions within 1 hour (limit {VELOCITY_MAX_TXNS})",
                            RULE_WEIGHTS["VELOCITY"]))
    return alerts


RULES = [rule_large_amount, rule_high_risk_country, rule_watchlist,
         rule_structuring, rule_velocity]


def run_rules(txns):
    alerts = []
    for rule in RULES:
        alerts.extend(rule(txns))
    return alerts


def severity(score):
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def score_by_transaction(alerts):
    """Aggregate alert scores per transaction."""
    scores = defaultdict(int)
    for a in alerts:
        scores[a.txn_id] += a.score
    return dict(scores)


# --------------------------------------------------------------------------
# Storage and reporting
# --------------------------------------------------------------------------
def save_alerts(db_path, alerts):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            txn_id TEXT, account_id TEXT, rule TEXT,
            description TEXT, score INTEGER,
            status TEXT DEFAULT 'OPEN',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )""")
    conn.executemany(
        "INSERT INTO alerts (txn_id, account_id, rule, description, score) VALUES (?,?,?,?,?)",
        [(a.txn_id, a.account_id, a.rule, a.description, a.score) for a in alerts],
    )
    conn.commit()
    conn.close()


def write_report(path, alerts):
    scores = score_by_transaction(alerts)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["txn_id", "account_id", "rule", "description",
                    "rule_score", "txn_total_score", "severity"])
        for a in sorted(alerts, key=lambda x: (-scores[x.txn_id], x.txn_id)):
            total = scores[a.txn_id]
            w.writerow([a.txn_id, a.account_id, a.rule, a.description,
                        a.score, total, severity(total)])


def print_summary(txns, alerts):
    scores = score_by_transaction(alerts)
    print(f"Transactions screened : {len(txns)}")
    print(f"Alerts raised         : {len(alerts)}")
    print(f"Transactions flagged  : {len(scores)}")
    by_rule = defaultdict(int)
    for a in alerts:
        by_rule[a.rule] += 1
    print("\nAlerts by rule:")
    for rule, n in sorted(by_rule.items(), key=lambda x: -x[1]):
        print(f"  {rule:<20} {n}")
    print("\nTop risky transactions:")
    for txn_id, s in sorted(scores.items(), key=lambda x: -x[1])[:5]:
        print(f"  {txn_id:<10} score={s:<4} severity={severity(s)}")


def main():
    parser = argparse.ArgumentParser(description="Financial transaction monitoring")
    parser.add_argument("input_csv", help="CSV file of transactions")
    parser.add_argument("--db", default="alerts.db", help="SQLite database for alerts")
    parser.add_argument("--report", default="alerts_report.csv", help="CSV compliance report")
    args = parser.parse_args()

    txns = load_transactions(args.input_csv)
    alerts = run_rules(txns)
    save_alerts(args.db, alerts)
    write_report(args.report, alerts)
    print_summary(txns, alerts)
    print(f"\nAlerts saved to {args.db}; report written to {args.report}")


if __name__ == "__main__":
    main()
