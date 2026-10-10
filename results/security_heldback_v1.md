# HELD-BACK security evaluation (set B)

Cases were written after the rules were tuned on set A. Small hand-written set;
this is not a benchmark and not evidence of real-world detection.

| Rule | Category | Cases | Caught by expected rule | Caught by any rule |
|---|---|---|---|---|
| ANY | evasion | 2 | 2 | 2 |
| SEC001 | evasion | 2 | 1 | 2 |
| SEC001 | plain | 5 | 1 | 1 |
| SEC002 | evasion | 3 | 0 | 3 |
| SEC002 | plain | 4 | 3 | 3 |
| SEC003 | evasion | 2 | 0 | 0 |
| SEC003 | plain | 6 | 4 | 4 |
| SEC004 | evasion | 2 | 1 | 1 |
| SEC004 | plain | 5 | 3 | 4 |
| SEC005 | evasion | 2 | 0 | 1 |
| SEC005 | plain | 7 | 3 | 3 |
| SEC006 | evasion | 1 | 1 | 1 |
| SEC006 | plain | 6 | 4 | 4 |
| SEC007 | plain | 3 | 3 | 3 |

**plain: 21 of 36 caught by the expected rule; 22 of 36 caught by any rule.**

**evasion: 5 of 14 caught by the expected rule; 10 of 14 caught by any rule.**

## Misses

- `b_net_urllib3` (plain, expected SEC001): fired nothing
- `b_net_ftp` (plain, expected SEC001): fired nothing
- `b_net_smtp` (plain, expected SEC001): fired nothing
- `b_net_websocket` (plain, expected SEC001): fired nothing
- `b_net_getattr_import` (evasion, expected SEC001): fired ['SEC008_DYNAMIC_ACCESS']
- `b_pipe_powershell` (plain, expected SEC002): fired nothing
- `b_pipe_procsubst` (evasion, expected SEC002): fired ['SEC001_NETWORK_CALL']
- `b_pipe_eval_subst` (evasion, expected SEC002): fired ['SEC001_NETWORK_CALL']
- `b_pipe_sh_c_two_step` (evasion, expected SEC002): fired ['SEC001_NETWORK_CALL']
- `b_exec_asyncio_shell` (plain, expected SEC003): fired nothing
- `b_exec_runpy` (plain, expected SEC003): fired nothing
- `b_exec_ctypes` (evasion, expected SEC003): fired nothing
- `b_exec_interp` (evasion, expected SEC003): fired nothing
- `b_obf_zlib_exec` (plain, expected SEC004): fired ['SEC003_COMMAND_EXEC']
- `b_obf_b32` (plain, expected SEC004): fired nothing
- `b_obf_map_chr` (evasion, expected SEC004): fired nothing
- `b_cred_proc_environ` (plain, expected SEC005): fired nothing
- `b_cred_netrc` (plain, expected SEC005): fired nothing
- `b_cred_git_credentials` (plain, expected SEC005): fired nothing
- `b_cred_boto3` (plain, expected SEC005): fired nothing
- `b_cred_environ_items` (evasion, expected SEC005): fired nothing
- `b_cred_printenv` (evasion, expected SEC005): fired ['SEC003_COMMAND_EXEC']
- `b_wf_circleci` (plain, expected SEC006): fired nothing
- `b_wf_azure` (plain, expected SEC006): fired nothing

Caught attacks reported HIGH/CRITICAL: 9 of 26

## False alarms on benign look-alikes: 1 of 16

- `b_ok_docs_dockerfile` fired ['SEC006_WORKFLOW_BUILD'] (severity MEDIUM)
