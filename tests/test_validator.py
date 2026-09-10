import unittest
from datetime import datetime, timezone
from pathlib import Path

from src.io_utils import load_cases
from src.models import RemediationCase
from src.reporting import portfolio_metrics, render_markdown
from src.validator import assess_all, assess_case


class NetworkRemediationValidationTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 9, 10, tzinfo=timezone.utc)
        self.data_path = Path("data/synthetic_remediation_cases.json")

    def test_loads_synthetic_cases(self):
        cases = load_cases(self.data_path)
        self.assertEqual(len(cases), 4)

    def test_validated_case_with_matching_state_has_no_gap(self):
        cases = load_cases(self.data_path)
        case = next(item for item in cases if item.case_id == "NET-002")
        self.assertEqual(assess_case(case, now=self.now), [])

    def test_implemented_without_evidence_is_flagged(self):
        cases = load_cases(self.data_path)
        case = next(item for item in cases if item.case_id == "NET-001")
        titles = {f.title for f in assess_case(case, now=self.now)}
        self.assertIn("Implementation lacks validation evidence", titles)

    def test_expected_observed_mismatch_is_flagged(self):
        cases = load_cases(self.data_path)
        case = next(item for item in cases if item.case_id == "NET-001")
        titles = {f.title for f in assess_case(case, now=self.now)}
        self.assertIn("Observed state does not match target state", titles)

    def test_expired_exception_is_flagged(self):
        cases = load_cases(self.data_path)
        case = next(item for item in cases if item.case_id == "NET-003")
        titles = {f.title for f in assess_case(case, now=self.now)}
        self.assertIn("Risk acceptance has expired", titles)

    def test_findings_are_sorted_by_score(self):
        findings = assess_all(load_cases(self.data_path), now=self.now)
        scores = [f.score for f in findings]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_finding_ids_are_deterministic(self):
        case = next(item for item in load_cases(self.data_path) if item.case_id == "NET-001")
        first = assess_case(case, now=self.now)
        second = assess_case(case, now=self.now)
        self.assertEqual([f.finding_id for f in first], [f.finding_id for f in second])

    def test_invalid_cidr_fails_closed(self):
        with self.assertRaises(ValueError):
            RemediationCase(
                case_id="BAD-1", asset="synthetic", owner="Owner", control_type="firewall",
                severity="high", status="open", source_zone="A", destination_zone="B",
                source_cidr="not-a-cidr", destination_cidr="10.0.0.0/24", service="TCP/443",
                opened_at=self.now, implemented_at=None, validated_at=None,
                validation_evidence=(), expected_state="blocked", observed_state="allowed"
            )

    def test_metrics_track_validated_cases(self):
        cases = load_cases(self.data_path)
        metrics = portfolio_metrics(cases, assess_all(cases, now=self.now))
        self.assertEqual(metrics["validated_cases"], 2)
        self.assertEqual(metrics["validation_rate_pct"], 50.0)

    def test_report_contains_governance_and_attack_context(self):
        cases = load_cases(self.data_path)
        report = render_markdown(cases, assess_all(cases, now=self.now))
        self.assertIn("Implementation is not equivalent to closure", report)
        self.assertIn("T1133", report)


if __name__ == "__main__":
    unittest.main()
