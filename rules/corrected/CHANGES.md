# Change notes for corrected rules

One line per fix: what was wrong, what I changed, and how I know it was wrong.

## T1070_v2.yml (log cleared)
Detection logic was already correct (4/4, 0 false positives, both mappings). Fixes are metadata only.

| What was wrong | What I changed | How I found it |
|---|---|---|
| `status: stable` on a rule that had never been tested | `status: experimental` | Sigma spec: *stable* is for rules proven in production |
| Rule `id` looked patterned (all three runs started with `3f…`), not a real random UUID | Generated a new UUID with `[guid]::NewGuid()` | Compared the three runs side by side |
| Run 1 listed `Microsoft-Windows-Security-Auditing` as a possible provider for event 1102 | Removed it from the `Provider_Name` list (no effect on detection, but it was factually wrong) | 1102 is written by `Microsoft-Windows-Eventlog` (confirmed in the sample logs and in Finding 3) |
| `fields` listed `SubjectUserName`/`SubjectDomainName`, but event 1102 stores the account under `UserData`, not `EventData`, so those columns are always empty | Removed them; kept `Computer`, `Channel`, `EventID` | Finding 3: the Event Data column was empty for every 1102 alert |
| ATT&CK tag `attack.t1070.001` | Kept, noted that current SigmaHQ uses `attack.t1685.005` | Compared with the current SigmaHQ rule |

## T1136_v2.yml (admin account) — based on run 1
Also added `related:` (type `derived`) pointing to the original AI rule's id, a new random `id`, and `author`/`modified` fields, in both v2 rules.

| What was wrong | What I changed | How I found it |
|---|---|---|
| Filter `TargetUserName|endswith: '$'` excluded every account ending in `$`, including the attacker's fake account named `$` | Removed the filter and its reference in the condition | Run 1 caught 2/4 events; runs 2–3 (no filter) caught 4/4. Inspecting run 2's hits showed `TargetUserName: $` in `DE_Fake_ComputerAccount_4720.evtx` |
| A known evasion technique was treated as noise | Added a false-positive note instead: machine accounts end in `$`, so tune by excluding known computer-account creation sources, not by name | SigmaHQ has a dedicated rule for `$` accounts (`win_security_new_or_renamed_user_account_with_dollar_sign.yml`) |

## T1059_v2.yml (encoded PowerShell)
| What was wrong | What I changed | How I found it |
|---|---|---|
| `|windash` modifier is not supported by Chainsaw v2.16.5, so the rule failed to load | Replaced it with explicit `-` and `/` variants (` -e `, ` /e `, ` -en `, ` /en `, ` -enc `, ` /enc `, ` -enco`, ` /enco`, ` -ec `, ` /ec `) | Chainsaw error: `unsupported modifiers - windash`. Removing the modifier made the same rule load. 82/82 SigmaHQ rules using `windash` also fail |
| Dropped SigmaHQ's `-Encoding` filter, so ` -enco` would also match the legitimate `-Encoding` parameter | Restored `filter_encoding: CommandLine|contains: ' -Encoding '` and `condition: all of selection_* and not filter_encoding` | Compared line by line with SigmaHQ `proc_creation_win_powershell_encode.yml` |
| Run 2 used ` -enc` without a trailing space (same `-Encoding` problem) | Covered by the restored filter | Read the rule |
