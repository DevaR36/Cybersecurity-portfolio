"""Unit tests for an offline, fictional AWS security posture exercise."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from examples.posture_audit import CHECKS, check_snapshot, compare, load_snapshot, main, summarize

BEFORE = json.loads((ROOT / "data/fictional_before.json").read_text(encoding="utf-8"))
AFTER = json.loads((ROOT / "data/fictional_after.json").read_text(encoding="utf-8"))


class TestPostureAudit(unittest.TestCase):
    def test_checks_are_unique(self):
        self.assertEqual(len(CHECKS), len({x.key for x in CHECKS}))

    def test_catalog_has_eleven(self):
        self.assertEqual(len(CHECKS), 11)

    def test_before_counts(self):
        self.assertEqual(summarize(check_snapshot(BEFORE))["flagged"], 5)

    def test_after_counts(self):
        self.assertEqual(summarize(check_snapshot(AFTER))["flagged"], 3)

    def test_before_passed(self):
        self.assertEqual(summarize(check_snapshot(BEFORE))["passed"], 6)

    def test_after_passed(self):
        self.assertEqual(summarize(check_snapshot(AFTER))["passed"], 8)

    def test_iam_mfa_resolves(self):
        self.assertIn("IAM-02", compare(check_snapshot(BEFORE), check_snapshot(AFTER))["resolved"])

    def test_ebs_resolves(self):
        self.assertIn("EC2-01", compare(check_snapshot(BEFORE), check_snapshot(AFTER))["resolved"])

    def test_unresolved_password_policy(self):
        self.assertIn("IAM-03", compare(check_snapshot(BEFORE), check_snapshot(AFTER))["still_flagged"])

    def test_unresolved_s3_transport(self):
        self.assertIn("S3-02", compare(check_snapshot(BEFORE), check_snapshot(AFTER))["still_flagged"])

    def test_unresolved_s3_versioning(self):
        self.assertIn("S3-03", compare(check_snapshot(BEFORE), check_snapshot(AFTER))["still_flagged"])

    def test_no_new_flags(self):
        self.assertEqual(compare(check_snapshot(BEFORE), check_snapshot(AFTER))["newly_flagged"], [])

    def test_false_not_accepted_for_length(self):
        s=copy.deepcopy(AFTER);s["iam"]["password_min_length"]=True
        self.assertIn("IAM-03", summarize(check_snapshot(s))["flagged_checks"])

    def test_length_exact_boundary(self):
        s=copy.deepcopy(AFTER);s["iam"]["password_min_length"]=14
        self.assertNotIn("IAM-03", summarize(check_snapshot(s))["flagged_checks"])

    def test_length_above_boundary(self):
        s=copy.deepcopy(AFTER);s["iam"]["password_min_length"]=20
        self.assertNotIn("IAM-03", summarize(check_snapshot(s))["flagged_checks"])

    def test_length_below_boundary(self):
        s=copy.deepcopy(AFTER);s["iam"]["password_min_length"]=13
        self.assertIn("IAM-03", summarize(check_snapshot(s))["flagged_checks"])

    def test_missing_field_flagged(self):
        s=copy.deepcopy(AFTER);s["cloudtrail"].pop("management_logging")
        self.assertIn("CT-01", summarize(check_snapshot(s))["flagged_checks"])

    def test_missing_service_flagged(self):
        s=copy.deepcopy(AFTER);s.pop("config")
        self.assertIn("CFG-01", summarize(check_snapshot(s))["flagged_checks"])

    def test_truthy_integer_not_a_boolean(self):
        s=copy.deepcopy(AFTER);s["iam"]["analyst_mfa"]=1
        self.assertIn("IAM-02", summarize(check_snapshot(s))["flagged_checks"])

    def test_nonboolean_string_flagged(self):
        s=copy.deepcopy(AFTER);s["iam"]["root_mfa"]="true"
        self.assertIn("IAM-01", summarize(check_snapshot(s))["flagged_checks"])

    def test_non_mapping_root_rejected(self):
        with self.assertRaises(ValueError):check_snapshot([])

    def test_nested_list_rejected_as_failed(self):
        s=copy.deepcopy(AFTER);s["s3"]["audit_bucket_tls_required"]=[]
        self.assertIn("S3-02", summarize(check_snapshot(s))["flagged_checks"])

    def test_invalid_json_error(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/"bad.json";f.write_text("{broken",encoding="utf-8")
            with self.assertRaises(ValueError):load_snapshot(f)

    def test_json_list_root_error(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/"list.json";f.write_text("[]",encoding="utf-8")
            with self.assertRaises(ValueError):load_snapshot(f)

    def test_nonexistent_file_error(self):
        with self.assertRaises(ValueError):load_snapshot(ROOT/"data/no-file.json")

    def test_oversized_file_error(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/"large.json";f.write_text(" " * 300000)
            with self.assertRaises(ValueError):load_snapshot(f)

    def test_comparison_rejects_different_keys(self):
        with self.assertRaises(ValueError):compare(check_snapshot(BEFORE), check_snapshot(AFTER)[1:])

    def test_original_unchanged(self):
        s=copy.deepcopy(BEFORE);check_snapshot(s);self.assertEqual(s,BEFORE)

    def test_cli_text_before_after(self):
        buf=io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(main([str(ROOT/"data/fictional_before.json"),str(ROOT/"data/fictional_after.json")]),0)
        self.assertIn("Before: 6/11 passed; 5 flagged",buf.getvalue())
        self.assertIn("After: 8/11 passed; 3 flagged",buf.getvalue())

    def test_cli_json_mode(self):
        buf=io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(main([str(ROOT/"data/fictional_before.json"),str(ROOT/"data/fictional_after.json"),"--json"]),0)
        self.assertEqual(json.loads(buf.getvalue())["resolved"],["EC2-01","IAM-02"])

    def test_cli_single_snapshot(self):
        buf=io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(main([str(ROOT/"data/fictional_before.json")]),0)
        self.assertIn("Snapshot: 6/11 passed",buf.getvalue())


if __name__ == "__main__":
    unittest.main()
