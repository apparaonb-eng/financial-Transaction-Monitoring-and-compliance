import unittest
from datetime import datetime, timedelta

import monitor
from monitor import Transaction


def txn(txn_id, minutes=0, account="A1", counterparty="Shop", country="IN", amount=100.0):
    base = datetime(2026, 11, 18, 9, 0)
    return Transaction(txn_id, base + timedelta(minutes=minutes), account,
                       counterparty, country, amount, "USD", "debit")


class RuleTests(unittest.TestCase):
    def test_large_amount(self):
        alerts = monitor.rule_large_amount([txn("T1", amount=10_000), txn("T2", amount=9_999)])
        self.assertEqual([a.txn_id for a in alerts], ["T1"])

    def test_high_risk_country(self):
        alerts = monitor.rule_high_risk_country([txn("T1", country="IR"), txn("T2")])
        self.assertEqual([a.txn_id for a in alerts], ["T1"])

    def test_watchlist_is_case_insensitive(self):
        alerts = monitor.rule_watchlist([txn("T1", counterparty="shadow trading llc")])
        self.assertEqual(len(alerts), 1)

    def test_structuring(self):
        txns = [txn(f"T{i}", minutes=i * 60, amount=9_500) for i in range(3)]
        alerts = monitor.rule_structuring(txns)
        self.assertEqual(len(alerts), 3)

    def test_no_structuring_for_small_amounts(self):
        txns = [txn(f"T{i}", minutes=i * 60, amount=500) for i in range(3)]
        self.assertEqual(monitor.rule_structuring(txns), [])

    def test_velocity(self):
        txns = [txn(f"T{i}", minutes=i * 5) for i in range(6)]
        self.assertEqual(len(monitor.rule_velocity(txns)), 6)

    def test_velocity_not_triggered_when_spread_out(self):
        txns = [txn(f"T{i}", minutes=i * 30) for i in range(6)]
        self.assertEqual(monitor.rule_velocity(txns), [])

    def test_severity_levels(self):
        self.assertEqual(monitor.severity(10), "LOW")
        self.assertEqual(monitor.severity(30), "MEDIUM")
        self.assertEqual(monitor.severity(55), "HIGH")
        self.assertEqual(monitor.severity(115), "CRITICAL")


if __name__ == "__main__":
    unittest.main()
