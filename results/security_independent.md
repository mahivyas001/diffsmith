# Independent security-scanner evaluation

Cases were written separately from the rules. All payloads are inert strings.
Detection here measures coverage on a small hand-written set, not real-world detection.

## Detection (malicious cases)

| Rule | Category | Cases | Caught by expected rule | Caught by any rule |
|---|---|---|---|---|
| SEC001 | evasion | 3 | 0 | 0 |
| SEC001 | plain | 5 | 5 | 5 |
| SEC002 | evasion | 3 | 0 | 3 |
| SEC002 | plain | 4 | 3 | 4 |
| SEC003 | evasion | 3 | 0 | 0 |
| SEC003 | plain | 6 | 6 | 6 |
| SEC004 | evasion | 2 | 0 | 0 |
| SEC004 | plain | 5 | 3 | 3 |
| SEC005 | evasion | 2 | 0 | 0 |
| SEC005 | plain | 6 | 3 | 3 |
| SEC006 | evasion | 2 | 0 | 0 |
| SEC006 | plain | 6 | 4 | 4 |
| SEC007 | evasion | 1 | 1 | 1 |
| SEC007 | plain | 4 | 3 | 3 |

## Misses (24)

- `net_dunder_import` (evasion, expected SEC001), fired: nothing
- `net_alias_import` (evasion, expected SEC001), fired: nothing
- `net_importlib` (evasion, expected SEC001), fired: nothing
- `pipe_shfile` (plain, expected SEC002), fired: ['SEC001_NETWORK_CALL']
- `pipe_cmdsubst` (evasion, expected SEC002), fired: ['SEC001_NETWORK_CALL']
- `pipe_two_step` (evasion, expected SEC002), fired: ['SEC001_NETWORK_CALL']
- `pipe_python_c` (evasion, expected SEC002), fired: ['SEC001_NETWORK_CALL']
- `exec_dunder_import` (evasion, expected SEC003), fired: nothing
- `exec_getattr` (evasion, expected SEC003), fired: nothing
- `exec_importlib` (evasion, expected SEC003), fired: nothing
- `obf_fromhex` (plain, expected SEC004), fired: nothing
- `obf_marshal` (plain, expected SEC004), fired: nothing
- `obf_chr_join` (evasion, expected SEC004), fired: nothing
- `obf_b64_alias` (evasion, expected SEC004), fired: nothing
- `cred_ssh_key` (plain, expected SEC005), fired: nothing
- `cred_passwd` (plain, expected SEC005), fired: nothing
- `cred_aws_file` (evasion, expected SEC005), fired: nothing
- `cred_environ_dump` (evasion, expected SEC005), fired: nothing
- `cred_keyring` (plain, expected SEC005), fired: nothing
- `wf_gitlab_ci` (plain, expected SEC006), fired: nothing
- `wf_tox` (evasion, expected SEC006), fired: nothing
- `wf_package_json` (plain, expected SEC006), fired: nothing
- `wf_dockerfile` (evasion, expected SEC006), fired: nothing
- `hook_husky` (plain, expected SEC007), fired: nothing

## False alarms on benign look-alikes: 0 of 14


## Arguable cases (not counted as false alarms)

- `arg_env_settings` fired ['SEC005_CREDENTIAL_READS']
- `arg_subprocess_git` fired ['SEC003_COMMAND_EXEC']
- `arg_b64_encode` fired nothing
