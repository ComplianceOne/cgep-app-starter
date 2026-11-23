"""Detection rule tests: each EventBridge pattern in terraform/detections/
is checked against real EventBridge matching via `aws events
test-event-pattern`, with events that must alert and events that must not.

Test names start with the HIPAA control the rule protects.

Run:  python3 -m unittest discover -s tests/detections -v
Needs AWS credentials with events:TestEventPattern (the read-only plan role
has it). Skips, rather than passes, when no credentials are available.
"""
import json
import pathlib
import subprocess
import unittest

PATTERNS = pathlib.Path(__file__).resolve().parents[2] / "terraform" / "detections"
ACCOUNT = "123456789012"
PIPELINE = {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/grc-pipeline-apply/gha",
            "sessionContext": {"sessionIssuer": {"type": "Role", "userName": "grc-pipeline-apply"}}}
ENGINEER = {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/engineer/jane",
            "sessionContext": {"sessionIssuer": {"type": "Role", "userName": "engineer"}}}
IAM_USER = {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/cgep-lab"}
ROOT = {"type": "Root", "arn": f"arn:aws:iam::{ACCOUNT}:root"}


def _aws_available():
    try:
        return subprocess.run(["aws", "sts", "get-caller-identity"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


AWS = _aws_available()


def api_call(source, event_source, name, who, request=None, detail_type="AWS API Call via CloudTrail"):
    return {
        "id": "7bf73129-1428-4cd3-a780-95db273d1602", "version": "0", "account": ACCOUNT,
        "time": "2026-11-22T06:17:00Z", "region": "us-east-1", "resources": [],
        "source": source, "detail-type": detail_type,
        "detail": {"eventSource": event_source, "eventName": name, "userIdentity": who,
                   "sourceIPAddress": "203.0.113.10", "requestParameters": request or {}},
    }


def s3(name, bucket, who):
    return api_call("aws.s3", "s3.amazonaws.com", name, who, {"bucketName": bucket})


@unittest.skipUnless(AWS, "no AWS credentials; detection tests need events:TestEventPattern")
class DetectionTest(unittest.TestCase):
    def matches(self, rule, event):
        pattern = (PATTERNS / f"{rule}.json").read_text()
        out = subprocess.run(
            ["aws", "events", "test-event-pattern", "--event-pattern", pattern,
             "--event", json.dumps(event), "--query", "Result", "--output", "text"],
            capture_output=True, text=True, check=True)
        return out.stdout.strip() == "True"

    def assertAlerts(self, rule, event):
        self.assertTrue(self.matches(rule, event), f"{rule} should alert")

    def assertQuiet(self, rule, event):
        self.assertFalse(self.matches(rule, event), f"{rule} should not alert")

    # 164.312(b) audit controls: the trail itself
    def test_164_312_b_stop_logging_alerts_even_from_pipeline(self):
        self.assertAlerts("audit-trail-tampering",
                          api_call("aws.cloudtrail", "cloudtrail.amazonaws.com", "StopLogging", PIPELINE))

    def test_164_312_b_delete_trail_by_iam_user_alerts(self):
        self.assertAlerts("audit-trail-tampering",
                          api_call("aws.cloudtrail", "cloudtrail.amazonaws.com", "DeleteTrail", IAM_USER))

    def test_164_312_b_reading_trail_status_is_quiet(self):
        self.assertQuiet("audit-trail-tampering",
                         api_call("aws.cloudtrail", "cloudtrail.amazonaws.com", "GetTrailStatus", ENGINEER))

    # 164.312(a)(2)(iv) encryption: key custody
    def test_164_312_a_2_iv_schedule_key_deletion_out_of_band_alerts(self):
        self.assertAlerts("kms-key-tampering", api_call("aws.kms", "kms.amazonaws.com", "ScheduleKeyDeletion", ENGINEER))

    def test_164_312_a_2_iv_key_policy_change_by_iam_user_alerts(self):
        self.assertAlerts("kms-key-tampering", api_call("aws.kms", "kms.amazonaws.com", "PutKeyPolicy", IAM_USER))

    def test_164_312_a_2_iv_key_policy_change_by_pipeline_is_quiet(self):
        self.assertQuiet("kms-key-tampering", api_call("aws.kms", "kms.amazonaws.com", "PutKeyPolicy", PIPELINE))

    def test_164_312_a_2_iv_decrypt_is_quiet(self):
        self.assertQuiet("kms-key-tampering", api_call("aws.kms", "kms.amazonaws.com", "Decrypt", ENGINEER))

    # 164.312(e)(1) transmission security / bucket protections
    def test_164_312_e_1_bucket_policy_deleted_out_of_band_alerts(self):
        self.assertAlerts("bucket-protection-change", s3("DeleteBucketPolicy", "acme-health-intake-uploads-fcc40870", ENGINEER))

    def test_164_312_e_1_versioning_change_by_iam_user_alerts(self):
        self.assertAlerts("bucket-protection-change", s3("PutBucketVersioning", "acme-health-intake-uploads-fcc40870", IAM_USER))

    def test_164_312_e_1_bucket_policy_change_by_pipeline_is_quiet(self):
        self.assertQuiet("bucket-protection-change", s3("PutBucketPolicy", "acme-health-intake-uploads-fcc40870", PIPELINE))

    def test_164_312_e_1_unrelated_bucket_is_quiet(self):
        self.assertQuiet("bucket-protection-change", s3("DeleteBucketPolicy", "someone-elses-bucket", ENGINEER))

    # 164.312(a)(1) access control: workload and pipeline roles
    def test_164_312_a_1_lambda_role_policy_change_out_of_band_alerts(self):
        self.assertAlerts("workload-iam-change", api_call("aws.iam", "iam.amazonaws.com", "PutRolePolicy", ENGINEER,
                                                          {"roleName": "acme-health-intake-lambda-fcc40870"}))

    def test_164_312_a_1_pipeline_role_trust_change_alerts(self):
        self.assertAlerts("workload-iam-change", api_call("aws.iam", "iam.amazonaws.com", "UpdateAssumeRolePolicy", IAM_USER,
                                                          {"roleName": "grc-pipeline-apply"}))

    def test_164_312_a_1_workload_role_change_by_pipeline_is_quiet(self):
        self.assertQuiet("workload-iam-change", api_call("aws.iam", "iam.amazonaws.com", "PutRolePolicy", PIPELINE,
                                                         {"roleName": "acme-health-intake-lambda-fcc40870"}))

    def test_164_312_a_1_unrelated_role_is_quiet(self):
        self.assertQuiet("workload-iam-change", api_call("aws.iam", "iam.amazonaws.com", "PutRolePolicy", ENGINEER,
                                                         {"roleName": "unrelated-role"}))

    # 164.312(c)(1) integrity: the evidence vault
    def test_164_312_c_1_evidence_delete_alerts_even_from_pipeline(self):
        self.assertAlerts("evidence-deletion-attempt", s3("DeleteObject", "acme-health-intake-evidence-fcc40870", PIPELINE))

    def test_164_312_c_1_evidence_retention_change_alerts(self):
        self.assertAlerts("evidence-deletion-attempt", s3("PutObjectRetention", "acme-health-intake-evidence-fcc40870", IAM_USER))

    def test_164_312_c_1_evidence_upload_is_quiet(self):
        self.assertQuiet("evidence-deletion-attempt", s3("PutObject", "acme-health-intake-evidence-fcc40870", PIPELINE))

    def test_164_312_c_1_delete_in_uploads_bucket_is_quiet(self):
        self.assertQuiet("evidence-deletion-attempt", s3("DeleteObject", "acme-health-intake-uploads-fcc40870", ENGINEER))

    # 164.308(a)(1)(ii)(D) activity review: root use
    def test_164_308_a_1_ii_d_root_api_call_alerts(self):
        self.assertAlerts("root-account-activity", api_call("aws.s3", "s3.amazonaws.com", "ListBuckets", ROOT))

    def test_164_308_a_1_ii_d_root_console_sign_in_alerts(self):
        self.assertAlerts("root-account-activity", api_call("aws.signin", "signin.amazonaws.com", "ConsoleLogin", ROOT,
                                                            detail_type="AWS Console Sign In via CloudTrail"))

    def test_164_308_a_1_ii_d_iam_user_activity_is_quiet(self):
        self.assertQuiet("root-account-activity", api_call("aws.s3", "s3.amazonaws.com", "ListBuckets", IAM_USER))


if __name__ == "__main__":
    unittest.main(verbosity=2)
