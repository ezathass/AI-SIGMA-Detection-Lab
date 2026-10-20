# Standardized prompts

Use the **exact same wording** for every technique so the test is fair. Only change the part in [brackets].
Always start a **fresh chat** for each prompt so earlier answers don't influence the next one.
Record the model name, version, and date in `results/results.csv`.

---

## Prompt 1: Generate the rule

> You are a detection engineer. Write a Sigma rule to detect the following activity on Windows:
>
> **[TECHNIQUE DESCRIPTION]**
>
> Requirements:
> - Use the standard Sigma rule format (title, id, status, description, references, author, date, tags, logsource, detection, condition, falsepositives, level).
> - Include the MITRE ATT&CK technique tag.
> - Use field names from standard Windows event logs.
> - Output only the YAML rule, nothing else.

### Technique descriptions (paste one per fresh chat)

| File name | [TECHNIQUE DESCRIPTION] |
|---|---|
| `T1070_v1.yml` | An attacker clears Windows event logs (such as the Security or System log) to hide their activity. |
| `T1136_v1.yml` | A new local user account is created, or a user is added to the local Administrators group. |

> **Why these two descriptions were broadened (record this in the method section):** the attack samples contain both Security-log (1102) and System-log (104) clearing, and account creation (4720) and admin-group additions (4732) appear in *separate* files, never as one sequence. The descriptions were adjusted **before** any AI prompt was sent, so the test matches the available data rather than penalizing the AI for a mismatch between the prompt and the dataset.
| `T1059_v1.yml` | PowerShell is launched with a Base64-encoded command (for example using -enc or -EncodedCommand) to hide what it runs. |

Save the answer **unchanged** as `rules/ai_generated/<file name>`. Do not fix anything yet. The mistakes are part of the results.

---

## Prompt 2: Contamination check (separate fresh chat, after testing)

> Is there an existing rule in the public SigmaHQ repository that detects **[same technique description]**? If so, reproduce that rule from memory as closely as you can, including its title and detection logic. Output only the YAML.

Then compare three things side by side:
1. The AI's rule from Prompt 1
2. The AI's "from memory" SigmaHQ rule from Prompt 2
3. The real SigmaHQ rule

Rate the similarity of #1 to #3:
- **Near-copy**: same title or same detection logic almost line for line → the AI likely reproduced a memorized rule
- **Similar logic**: same event IDs/fields, written differently
- **Different**: its own approach

---

## Prompt 3 (optional): Ask the AI to fix its own rule

If the v1 rule fails, before fixing it yourself, give the AI the Chainsaw error or the missed case:

> Your rule [failed with this error / missed this event / fired on this normal event]: **[paste]**. Fix the rule. Output only the YAML.

Save as `rules/ai_generated/T####_v1b.yml` and test it too. This shows whether AI can debug its own work, which is a good point for the report.
