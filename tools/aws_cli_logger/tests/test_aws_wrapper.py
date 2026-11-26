"""Redaction behaviour of the logging wrapper, run against a fake `aws` binary."""
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

WRAPPER = Path(__file__).resolve().parents[1] / "aws"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(
    not BASH or subprocess.run([BASH, "-c", '[ "${BASH_VERSINFO[0]}" -ge 5 ]']).returncode != 0,
    reason="needs bash 5+",
)

AKID = "ASIAEXAMPLE0000TEST"
SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
TOKEN = "IQoJb3JpZ2luX2VjEXAMPLE" + "A" * 120
STS_JSON = (
    '{\n    "Credentials": {\n        "AccessKeyId": "%s",\n        "SecretAccessKey": "%s",\n'
    '        "SessionToken": "%s",\n        "Expiration": "2026-11-26T00:00:00+00:00"\n    }\n}\n' % (AKID, SECRET, TOKEN)
)


@pytest.fixture
def run(tmp_path):
    out_file = tmp_path / "fake_out"
    err_file = tmp_path / "fake_err"
    fake = tmp_path / "fakebin" / "aws"
    fake.parent.mkdir()
    fake.write_text('#!/bin/sh\ncat "$FAKE_OUT"\ncat "$FAKE_ERR" >&2\nexit "${FAKE_RC:-0}"\n')
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    logs = tmp_path / "logs"

    def _run(args, out="", err="", **env):
        out_file.write_text(out)
        err_file.write_text(err)
        e = {
            "PATH": os.environ["PATH"], "HOME": str(tmp_path), "AWS_LOG_DIR": str(logs),
            "AWS_REAL_BIN": str(fake), "FAKE_OUT": str(out_file), "FAKE_ERR": str(err_file), **env,
        }
        r = subprocess.run([BASH, str(WRAPPER), *args], env=e, capture_output=True, text=True, timeout=60)
        log = "".join(p.read_text() for p in sorted(logs.glob("aws-cli_*.log")))
        return r, log

    return _run


def test_passthrough_output_is_unchanged_even_when_logging_redacts(run):
    r, log = run(["sts", "assume-role", "--role-arn", "arn:aws:iam::111122223333:role/x"], out=STS_JSON)
    assert r.stdout == STS_JSON
    assert SECRET not in log and TOKEN not in log


def test_sensitive_command_stdout_is_not_logged(run):
    r, log = run(["secretsmanager", "get-secret-value", "--secret-id", "prod/db"], out='{"SecretString": "hunter2hunter2"}\n')
    assert "hunter2" not in log
    assert "stdout=suppressed(sensitive-command)" in log
    assert " OUT " not in log
    assert r.stdout == '{"SecretString": "hunter2hunter2"}\n'


def test_sensitive_command_stderr_is_still_logged_and_redacted(run):
    _, log = run(["sts", "get-session-token"], err='error: bad token="abc123secretvalue"\n', FAKE_RC="254")
    assert " ERR " in log and "abc123secretvalue" not in log and "exit=254" in log


def test_json_keys_redacted_in_ordinary_command_output(run):
    out = '{"Name": "app", "ClientSecret": "s3cr3t-value", "Password": "p4ss", "NextToken": "page2"}\n'
    _, log = run(["cognito-idp", "describe-user-pool-client"], out=out)
    assert "s3cr3t-value" not in log and "p4ss" not in log
    assert '"Name": "app"' in log and '"ClientSecret": "<redacted>"' in log
    assert "page2" in log  # pagination tokens are kept


def test_yaml_and_table_formats_redacted(run):
    out = "SecretAccessKey: abc123EXAMPLEsecret\n|  SessionToken  |  zzzEXAMPLEtoken  |\nplain line\n"
    _, log = run(["foo", "bar"], out=out)
    assert "abc123EXAMPLEsecret" not in log and "zzzEXAMPLEtoken" not in log
    assert "plain line" in log


def test_session_token_blob_redacted_without_key(run):
    _, log = run(["foo", "bar"], out=f"here: {TOKEN}\n")
    assert TOKEN not in log


def test_secret_option_values_redacted_in_logged_command(run):
    _, log = run(["secretsmanager", "create-secret", "--name", "n", "--secret-string", "topsecretvalue",
                  "--client-secret=eqsecretvalue"])
    assert "topsecretvalue" not in log and "eqsecretvalue" not in log
    assert "--secret-string '<redacted>'" in log and "--client-secret=<redacted>" in log
    assert "--name n" in log


def test_ssm_put_parameter_value_and_configure_set_redacted(run):
    _, log = run(["ssm", "put-parameter", "--name", "/a", "--value", "paramsecret"])
    assert "paramsecret" not in log
    _, log2 = run(["configure", "set", "aws_secret_access_key", "cfgsecretvalue", "--profile", "p"])
    assert "cfgsecretvalue" not in log2 and "--profile p" in log2


def test_output_none_logs_no_stdout_or_stderr(run):
    _, log = run(["ec2", "describe-vpcs"], out="visible?\n", err="warn\n", AWS_LOG_OUTPUT="none")
    assert " OUT " not in log and " ERR " not in log
    assert "output=off(AWS_LOG_OUTPUT=none)" in log and "END exit=0" in log


def test_ordinary_output_is_still_logged(run):
    _, log = run(["ec2", "describe-vpcs"], out='{"VpcId": "vpc-0abc"}\n')
    assert 'OUT {"VpcId": "vpc-0abc"}' in log


def test_log_file_is_private(run, tmp_path):
    run(["ec2", "describe-vpcs"], out="x\n")
    f = next((tmp_path / "logs").glob("aws-cli_*.log"))
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
