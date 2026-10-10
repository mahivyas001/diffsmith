# Independent security-scanner evaluation

Cases were written separately from the rules. All payloads are inert strings.
Detection here measures coverage on a small hand-written set, not real-world detection.

## Detection (malicious cases)

| Rule | Category | Cases | Caught by expected rule | Caught by any rule |
|---|---|---|---|---|
| SEC001 | evasion | 3 | 0 | 2 |
| SEC001 | plain | 5 | 5 | 5 |
| SEC002 | evasion | 3 | 3 | 3 |
| SEC002 | plain | 4 | 4 | 4 |
| SEC003 | evasion | 3 | 0 | 3 |
| SEC003 | plain | 6 | 6 | 6 |
| SEC004 | evasion | 2 | 0 | 1 |
| SEC004 | plain | 5 | 5 | 5 |
| SEC005 | evasion | 2 | 2 | 2 |
| SEC005 | plain | 6 | 6 | 6 |
| SEC006 | evasion | 2 | 2 | 2 |
| SEC006 | plain | 6 | 6 | 6 |
| SEC007 | evasion | 1 | 1 | 1 |
| SEC007 | plain | 4 | 4 | 4 |

## Misses (8)

- `net_dunder_import` (evasion, expected SEC001), fired: ['SEC008_DYNAMIC_ACCESS']
- `net_alias_import` (evasion, expected SEC001), fired: nothing
- `net_importlib` (evasion, expected SEC001), fired: ['SEC008_DYNAMIC_ACCESS']
- `exec_dunder_import` (evasion, expected SEC003), fired: ['SEC008_DYNAMIC_ACCESS']
- `exec_getattr` (evasion, expected SEC003), fired: ['SEC008_DYNAMIC_ACCESS']
- `exec_importlib` (evasion, expected SEC003), fired: ['SEC008_DYNAMIC_ACCESS']
- `obf_chr_join` (evasion, expected SEC004), fired: ['SEC008_DYNAMIC_ACCESS']
- `obf_b64_alias` (evasion, expected SEC004), fired: nothing

## Severity of caught attacks

- `net_urlopen` (plain, SEC001): MEDIUM
- `net_socket` (plain, SEC001): MEDIUM
- `net_httpclient` (plain, SEC001): MEDIUM
- `net_httpx` (plain, SEC001): MEDIUM
- `net_aiohttp` (plain, SEC001): MEDIUM
- `pipe_sh` (plain, SEC002): CRITICAL
- `pipe_bash_wget` (plain, SEC002): CRITICAL
- `pipe_shfile` (plain, SEC002): CRITICAL
- `pipe_cmdsubst` (evasion, SEC002): CRITICAL
- `pipe_two_step` (evasion, SEC002): CRITICAL
- `pipe_python_c` (evasion, SEC002): CRITICAL
- `pipe_makefile` (plain, SEC002): CRITICAL
- `exec_system` (plain, SEC003): MEDIUM
- `exec_popen` (plain, SEC003): MEDIUM
- `exec_subprocess_sh` (plain, SEC003): MEDIUM
- `exec_eval` (plain, SEC003): MEDIUM
- `exec_compile` (plain, SEC003): MEDIUM
- `exec_pty` (plain, SEC003): MEDIUM
- `obf_b64_exec` (plain, SEC004): MEDIUM
- `obf_rot13` (plain, SEC004): MEDIUM
- `obf_zlib_b64` (plain, SEC004): MEDIUM
- `obf_fromhex` (plain, SEC004): MEDIUM
- `obf_marshal` (plain, SEC004): MEDIUM
- `cred_aws_env` (plain, SEC005): HIGH
- `cred_gh_token` (plain, SEC005): HIGH
- `cred_ssh_key` (plain, SEC005): HIGH
- `cred_passwd` (plain, SEC005): HIGH
- `cred_dotenv` (plain, SEC005): low
- `cred_aws_file` (evasion, SEC005): HIGH
- `cred_environ_dump` (evasion, SEC005): low
- `cred_keyring` (plain, SEC005): HIGH
- `wf_new_workflow` (plain, SEC006): MEDIUM
- `wf_setup_cmdclass` (plain, SEC006): HIGH
- `wf_requirements` (plain, SEC006): MEDIUM
- `wf_pyproject_dep` (plain, SEC006): MEDIUM
- `wf_gitlab_ci` (plain, SEC006): MEDIUM
- `wf_tox` (evasion, SEC006): MEDIUM
- `wf_package_json` (plain, SEC006): MEDIUM
- `wf_dockerfile` (evasion, SEC006): MEDIUM
- `hook_git_hook` (plain, SEC007): HIGH
- `hook_husky` (plain, SEC007): HIGH
- `hook_postinstall` (plain, SEC007): HIGH
- `hook_precommit_cfg` (plain, SEC007): HIGH
- `hook_setup_cmdclass` (evasion, SEC007): HIGH

Caught attacks reported HIGH or CRITICAL: 19 of 44


## False alarms on benign look-alikes: 0 of 14


## Arguable cases (not counted as false alarms)

- `arg_env_settings` fired ['SEC005_CREDENTIAL_READS'] (max severity low)
- `arg_subprocess_git` fired ['SEC003_COMMAND_EXEC'] (max severity MEDIUM)
- `arg_b64_encode` fired nothing (max severity none)
