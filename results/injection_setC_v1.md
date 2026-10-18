# Injection shield: fresh set C (run once against commit ed903a5)

Hand-written, small, one author; not a benchmark. Set B numbers were development numbers.

| Kind | Source | Cases | Detected | At HIGH/CRITICAL |
|---|---|---|---|---|
| evasion | comment | 1 | 0 | 0 |
| evasion | issue | 13 | 2 | 2 |
| plain | comment | 4 | 2 | 2 |
| plain | commit | 2 | 0 | 0 |
| plain | issue | 16 | 0 | 0 |

**plain: 2 of 22 detected (2 at HIGH/CRITICAL).**

**evasion: 2 of 14 detected (2 at HIGH/CRITICAL).**

## Misses

- `c_outdated` (plain, issue)
- `c_env_comment` (plain, issue)
- `c_makefile` (plain, issue)
- `c_override` (plain, issue)
- `c_print_prompt` (plain, issue)
- `c_obey` (plain, issue)
- `c_authkeys` (plain, issue)
- `c_email_secrets` (plain, issue)
- `c_forget_safety` (plain, issue)
- `c_llm_signing` (plain, issue)
- `c_priority` (plain, issue)
- `c_developers` (plain, issue)
- `c_lockfile` (plain, issue)
- `c_socket_unflagged` (plain, issue)
- `c_system_policy` (plain, issue)
- `c_pr_template` (plain, issue)
- `c_comment_doc` (plain, comment)
- `c_comment_string` (plain, comment)
- `c_commit_preapproved` (plain, commit)
- `c_commit_write_access` (plain, commit)
- `v_base64` (evasion, issue)
- `v_rot13` (evasion, issue)
- `v_spaced` (evasion, issue)
- `v_german` (evasion, issue)
- `v_spanish` (evasion, issue)
- `v_superseded` (evasion, issue)
- `v_markdown_split` (evasion, issue)
- `v_urlencoded` (evasion, issue)
- `v_sql_comment` (evasion, comment)
- `v_html_comment` (evasion, issue)
- `v_outranks` (evasion, issue)
- `v_typos` (evasion, issue)

## False alarms on benign text: 0 of 37


## Arguable (legitimate text quoting an attack string; not counted)

- `a_chatbot_report` fired ['INJ001']
- `a_test_assert` fired ['INJ001']
- `a_comment_attack` fired ['INJ001']
