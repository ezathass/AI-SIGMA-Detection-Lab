# Findings log

Write each finding the day you find it, with the evidence. These become the "Key findings" and "What went wrong" sections of the report.

---

## Finding 1: Toolchain smoke test (Oct 12)
- Chainsaw v2.16.5 loaded **2,300** SigmaHQ Windows rules; **118 did not load** (about 5%, unsupported features).
- Ran against **278** EVTX-ATTACK-SAMPLES files: **1,016 detections on 802 events**, in about 4 seconds.
- Release integrity verified with SHA-256 against the GitHub release page.

## Finding 2: Selection bias in picking attack samples (Oct 12)
- First pass picked attack samples from the SigmaHQ smoke-test results.
- Problem: that only shows files SigmaHQ already detects, so the baseline would look perfect by construction.
- Fix: cross-checked with an independent `chainsaw search` by Event ID, which doesn't depend on any Sigma rule.

## Finding 3: SigmaHQ "Security Eventlog Cleared" rule silently misses every 1102 event (Oct 12)
- `chainsaw search` found **24** Event ID 1102 (Security log cleared) events across the samples.
- The SigmaHQ smoke test detected **0** of them.
- The rule (`win_security_audit_log_cleared.yml`) **passes lint** and loads fine, but finds **0 detections** even on `DE_1102_security_log_cleared.evtx`.
- **Root cause:** Chainsaw's default mapping (`sigma-event-logs-all.yml`, lines 203-205) restricts `logsource.service: security` to events from provider `Microsoft-Windows-Security-Auditing`. Event 1102 is logged by provider `Microsoft-Windows-Eventlog`, so it is filtered out before the rule is evaluated.
- **Impact:** a high-severity rule for a core defense-evasion technique fails with no error or warning.
- **Fix tested (Oct 12):** made a copy of the mapping (`sigma-event-logs-all-FIXED.yml`) and changed the `service: security` filter to allow both providers (`Microsoft-Windows-Security-Auditing` **and** `Microsoft-Windows-Eventlog`). The SigmaHQ rule went from **0 → 2 detections** on the T1070 test set (both 1102 events: `DE_1102_security_log_cleared.evtx` and the recording-artifact clear in `LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx`). Full dataset (all 278 sample files): **0 / 24 with the default mapping → 24 / 24 with the fix.**
- **Side effect noticed:** even with the fix, the **Event Data column is empty** for these alerts. Event 1102 stores who cleared the log under `UserData`, not `EventData`, so the default output doesn't show the account responsible. An analyst would see the alert but not the username.
- **All rules in this project are tested with both mappings** (default and FIXED) so the results show whether a rule depends on this blind spot.
- **Lesson:** rules must be validated in the actual toolchain, not just checked for correct syntax. This applies to AI-generated rules and trusted public rules alike.

## Finding 4: Ground truth for 1102 (Oct 12)
- 23 of the 24 files with a 1102 event are not log-clearing attacks: the researcher cleared the Security log before recording each scenario (a recording artifact).
- Only `DE_1102_security_log_cleared.evtx` represents the technique itself.
- Decision: a rule firing on these events counts as a *correct detection of the event*, but the report distinguishes "technique sample" from "recording artifact".

## Finding 5: Dataset shaped the prompts (Oct 12)
- Samples contain both 1102 (Security) and 104 (System) log clearing → T1070 description broadened to "event logs (such as Security or System)".
- Account creation (4720) and admin-group addition (4732) appear in separate files, never as a sequence → T1136 description changed from "created and then added" to "created, or added".
- Both changes made **before** any prompt was sent to the AI.

## Note: MITRE ATT&CK IDs
- SigmaHQ now tags log clearing as `attack.t1685.005` (not T1070.001). Verify current ATT&CK IDs before finalizing the report.

## Note: Antivirus during setup
- Windows Defender flagged/quarantined some sample and SigmaHQ regression files (Mimikatz, AggBITSAbuse signatures). Handled by quarantining and substituting other samples, **not** by disabling Defender or adding exclusions.

## Finding 6: T1070 results: AI rules beat the default SigmaHQ setup (Oct 13)
- Same prompt, 3 fresh temporary chats → 3 rules. **Detection logic identical** across runs (EventID 1102 Security + 104 System, `Provider_Name: Microsoft-Windows-Eventlog`, `level: high`); only wording, false-positive notes and output fields differed.
- All 3 AI rules: **4/4 attack events caught, 0 false positives** on my benign logs, with **both** the default and FIXED mapping.
- SigmaHQ baseline (2 rules: Security log cleared + System log cleared): **2/4 default mapping** (misses both 1102s) → **4/4 with FIXED mapping**, 0 false positives.
- **Why the AI did better by default:** its rules use `logsource: product: windows` with a `Channel` field instead of `service: security`, so Chainsaw's provider filter never applied. Not "smarter": a different design. Trade-off: no specific log source means the rule is evaluated against every event, and converted SIEM queries can be broader and more expensive.
- **AI mistakes noticed (no impact on detection):** run 1 lists `Microsoft-Windows-Security-Auditing` as a possible 1102 provider (incorrect); all runs set `status: stable` for an untested rule (overclaim); rule IDs all start with `3f…` (LLM "random" UUIDs look patterned); run 3 uses `ComputerName` instead of `Computer`; ATT&CK tag `t1070.001` while current SigmaHQ uses `t1685.005`.
- **Contamination check (by reading):** similar logic to SigmaHQ, but not a copy: SigmaHQ uses `service: security` plus legacy Event 517 and splits 104 into a separate rule.
- **Caveat:** T1070 is a single-Event-ID technique, the easiest case. Harder tests: T1136 (machine-account edge case) and T1059 (many command-line variants).

## Context: benign baseline noise (Oct 13)
- All 2,300 SigmaHQ rules on my own normal logs (Security, System, PowerShell): **109 detections on 108 events**.
- 68 of 109 (62%) are a single **informational** rule (User Logoff Event). The rest: Windows housekeeping, a PowerShell execution-policy change, and one **"Suspicious Connection to Remote Account"** false positive caused by the legitimate `uv` (Python tool) installer script using `NetworkCredential` for proxy auth.
- Lesson: even expert rules fire on normal activity, so rule **severity level** matters for triage.

## Finding 7: T1136: one of three "identical" AI answers had an attacker-exploitable blind spot (Oct 13)
- Model: Claude (fresh chats). Same prompt ×3.
- Runs 2 and 3: EventID 4720 OR (4732 AND TargetSid S-1-5-32-544) → **4/4 events caught**, 0 false positives.
- **Run 1 added a noise filter `TargetUserName|endswith: '$'`** (exclude machine accounts) → **2/4 caught**: it missed both 4720 events in `DE_Fake_ComputerAccount_4720.evtx`, where the attacker created an account named `$` precisely to look like a machine account. Confirmed by inspecting run 2's hits (`TargetUserName: $`).
- SigmaHQ baseline (3 rules) → **4/4 events (6 detections)**, 0 false positives. SigmaHQ even ships a **dedicated rule for `$` accounts** (`win_security_new_or_renamed_user_account_with_dollar_sign.yml`): the expert library hunts the exact trick the AI filtered out.
- Mapping made no difference (4720/4732 come from the standard Security-Auditing provider).
- **Lesson:** LLM output varies between runs in ways that change security outcomes. A plausible-sounding "reduce false positives" choice can encode a known evasion. Consistency has to be tested, not assumed, and every AI rule needs adversarial test cases.
- Corrected v2 = run 1 with the `$` filter removed.

## Finding 8: T1059: all 3 AI rules unusable in Chainsaw (`windash`), and the AI copied a public rule (Oct 13)
- Model: Claude, 3 fresh chats. All three rules failed to load: Chainsaw error **`unsupported modifiers - windash`**. Removing `|windash` makes the same rule load (proven with a debug copy).
- **82 of 82** SigmaHQ Windows rules that use `windash` also fail to load in Chainsaw v2.16.5. That accounts for **82 of the 118** rules that didn't load in the smoke test (69%).
- **Contamination confirmed:** runs 1 and 3 contain the **same 5 dash variants in the same order** (`' -e '`, `' -en '`, `' -enc '`, `' -enco'`, `' -ec '`) as SigmaHQ's `proc_creation_win_powershell_encode.yml` ("Suspicious Execution of Powershell with Base64"). The AI reproduced a public rule, **added** the newer `windash` modifier, and **dropped** SigmaHQ's `' -Encoding '` false-positive filter (needed because `' -enco'` also matches the benign `-Encoding` parameter). Run 2 used `' -enc'` with no trailing space, which would also match `-Encoding`.
- **Corrected v2:** `windash` replaced with explicit `-` and `/` variants; `-Encoding` filter restored → loads; **1/5** attack files caught (IIS webshell sample).
- **SigmaHQ baseline** (2 encoded-command rules): **1/5**, the same file (2 detections on 1 event).
- **Ground truth caveat:** most samples hide Base64 *without* the `-enc` flag (FromBase64String, gzip, script block 4104). A flag-based rule should not catch them. SigmaHQ covers those with *other* rules. Lesson: one technique often needs several complementary rules.
- **False-positive test not meaningful for T1059:** my benign logs have no process-creation events (no Sysmon, 4688 auditing off by default), so "0 false positives" proves nothing here. Stated as a limitation.

### Finding 8b: T1059 ground truth (Oct 13)
Keyword search per attack file (`chainsaw search -i`):

| File | encodedcommand | ` -enc ` | ` -e ` | frombase64string | gzip |
|---|---|---|---|---|---|
| discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx | 0 | **40** | 0 | 0 | 0 |
| LM_sysmon_psexec_smb_meterpreter.evtx | 0 | 0 | 0 | 4 | 4 |
| panache_sysmon_vs_EDRTestingScript.evtx | 0 | 0 | 0 | 0 | 0 |
| phish_windows_credentials_powershell_scriptblockLog_4104.evtx | 0 | 0 | 0 | 1 | 1 |
| susp_explorer_exec.evtx | 0 | 0 | 0 | 1 | 0 |

- **Only 1 of 5 samples uses the `-enc` flag** described in the prompt. Corrected v2 and the SigmaHQ baseline both caught it: **1/1 true positives**. The other 4 use different obfuscation methods (FromBase64String, gzip, script-block decoding, other patterns) that a flag-based rule is not meant to catch.
- **Methodology error, owned:** T1059 samples were chosen by searching SigmaHQ detection names for "encod|base64", which was broader than the technique as prompted. Labelling ground truth *before* testing would have caught this. Future work: separate prompts and rules for each obfuscation sub-method.
- The 40 ` -enc ` hits in the IIS file are likely the same encoded command appearing in other events (e.g. child-process parent command lines); the rule fires once, on the PowerShell launch itself.

## Finding 9: Corrected v2 rules verified (Oct 15)
- **T1070_v2:** 4/4 attack events, 0 benign, identical with default and FIXED mapping. Metadata-only fixes confirmed not to change detection.
- **T1136_v2:** removing the `$` filter took run 1 from **2/4 → 4/4** (the fake `$` account is now caught), still **0 false positives** on benign logs, both mappings.
- All three corrected rules pass `chainsaw lint` and load.
