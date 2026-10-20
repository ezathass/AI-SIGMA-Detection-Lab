# Step-by-step guide (Windows)

Follow in order. Each step says what "done" looks like.
All commands go in **PowerShell**. Open it from the Start menu.
Lines starting with `#` are comments, don't type them.

**Deadline plan:** Wed = Steps 1-4 (go/no-go). Thu-Fri = Steps 5-8. Sat = Step 9. Sun = submit.

---

## Step 1: Make the lab folder (2 min)

```powershell
mkdir D:\lab
mkdir D:\lab\out
```
**Done when:** `D:\lab` exists.

---

## Step 2: Download the three things (20 min)

1. **Chainsaw.** Go to https://github.com/WithSecureLabs/chainsaw/releases. Under the latest release, download the **all-in-one package** (the zip that says it includes rules and examples, e.g. something like `chainsaw_all_platforms+rules+examples.zip`). Extract it to `D:\lab\chainsaw`.
2. **SigmaHQ rules.** Go to https://github.com/SigmaHQ/sigma, click **Code → Download ZIP**. Extract to `D:\lab\sigma`.
3. **Attack samples.** Go to https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES, click **Code → Download ZIP**. Extract to `D:\lab\samples`.

> If Windows Defender flags something in the samples: they're log files, not programs, but some contain attack strings like "mimikatz" that antivirus reacts to. You only need 3 techniques, so if a file gets quarantined, just skip it. **Don't** turn Defender off.

**Done when:** you have `D:\lab\chainsaw`, `D:\lab\sigma`, `D:\lab\samples`.

---

## Step 3: Find the Chainsaw program and mapping file (5 min)

```powershell
cd D:\lab\chainsaw
# find the Windows program (name ends in .exe)
Get-ChildItem -Recurse -Filter *.exe | Select-Object FullName
# find the mapping file Chainsaw needs to read Sigma rules
Get-ChildItem -Recurse -Filter sigma-event-logs-all.yml | Select-Object FullName
```
Write down both paths. If the .exe has a long name, rename it to `chainsaw.exe` and move it to `D:\lab\chainsaw\`. The commands below assume:
- program: `D:\lab\chainsaw\chainsaw.exe`
- mapping: `D:\lab\chainsaw\mappings\sigma-event-logs-all.yml`

Change them if yours are different.

```powershell
D:\lab\chainsaw\chainsaw.exe --help
```
**Done when:** the help text prints.

---

## Step 4: GO / NO-GO test (15 min) ⚠️ do this Wednesday

Run all SigmaHQ Windows rules against all the attack samples:

```powershell
cd D:\lab\chainsaw
.\chainsaw.exe hunt D:\lab\samples -s D:\lab\sigma\rules\windows --mapping .\mappings\sigma-event-logs-all.yml --csv --output D:\lab\out\smoketest
```

**GO:** it runs and creates CSV files in `D:\lab\out\smoketest` with detections in them. Continue to Step 5.

**NO-GO:** errors you can't fix in about 1 hour. Copy the error and send it to me. If it's still broken Wednesday night, switch to the backup project (vulnerability prioritization) on Thursday.

> Chainsaw may print warnings about rules it can't load. That's normal: some SigmaHQ rules use features Chainsaw doesn't support. Only worry if nothing runs at all.

---

## Step 5: Find attack samples for each technique (30 min)

Use Chainsaw's search to find which sample files contain each event.

```powershell
cd D:\lab\chainsaw
# T1070 log cleared
.\chainsaw.exe search -t 'Event.System.EventID: =1102' D:\lab\samples
.\chainsaw.exe search -t 'Event.System.EventID: =104' D:\lab\samples
# T1136 account created / added to a group
.\chainsaw.exe search -t 'Event.System.EventID: =4720' D:\lab\samples
.\chainsaw.exe search -t 'Event.System.EventID: =4732' D:\lab\samples
# T1059 encoded PowerShell (keyword search, -i = ignore case)
.\chainsaw.exe search -i "encodedcommand" D:\lab\samples
.\chainsaw.exe search -i " -enc " D:\lab\samples
```

Look at the results to see which files the hits came from. If the file name isn't obvious in the output, run the search on one tactic folder at a time (e.g. `D:\lab\samples\Defense Evasion`) to narrow it down.

Copy the matching files into:
```
D:\lab\data\attack\T1070\
D:\lab\data\attack\T1136\
D:\lab\data\attack\T1059\
```
Aim for **2-5 files per technique**. Write the exact file names down for the README.

**Done when:** each of the three folders has at least 2 .evtx files.

---

## Step 6: Export your own normal logs (10 min)

Open PowerShell **as Administrator** (right-click → Run as administrator):

```powershell
mkdir D:\lab\data\benign
wevtutil epl Security D:\lab\data\benign\Security.evtx
wevtutil epl System D:\lab\data\benign\System.evtx
wevtutil epl "Microsoft-Windows-PowerShell/Operational" D:\lab\data\benign\PowerShell.evtx
```

> **Do not** clear your logs or create test admin accounts to "make" events. The benign set is just your normal activity. Keep these files private: they have your username and computer name in them.

**Done when:** three .evtx files are in `D:\lab\data\benign`.

---

## Step 7: Generate and test each AI rule (about 1.5 h per technique)

Repeat for T1070, T1136, T1059.

**7a. Generate.** Open a fresh AI chat. Paste Prompt 1 from `prompts\prompt_template.md` with that technique's description. Save the answer **unchanged** as e.g. `D:\lab\rules\T1070_v1.yml`, and also into the repo's `rules/ai_generated/`.

**7b. Test against attack samples.**
```powershell
cd D:\lab\chainsaw
.\chainsaw.exe hunt D:\lab\data\attack\T1070 -s D:\lab\rules\T1070_v1.yml --mapping .\mappings\sigma-event-logs-all.yml --csv --output D:\lab\out\T1070_v1_attack
```
> If Chainsaw won't accept a single file after `-s`, put the rule alone in a folder (e.g. `D:\lab\rules\T1070_v1\`) and point `-s` at that folder.

**7c. Test against your normal logs.**
```powershell
.\chainsaw.exe hunt D:\lab\data\benign -s D:\lab\rules\T1070_v1.yml --mapping .\mappings\sigma-event-logs-all.yml --csv --output D:\lab\out\T1070_v1_benign
```

> **Since Oct 12: test every rule with BOTH mappings.** Run 7b and 7c twice: once with `.\mappings\sigma-event-logs-all.yml` (default) and once with `.\mappings\sigma-event-logs-all-FIXED.yml`. Record both in `results.csv` (add the mapping in the notes column). See Finding 3 in `results/findings_log.md`.

**7d. Record** in `results.csv`: did it load? How many attack files did it catch / miss? Any hits on benign logs?

**7e. Fix it.** If it failed or missed things, figure out why. Compare its `logsource` and field names with what's actually in the logs. Save your fixed version as `T1070_v2.yml`, write each change in `rules/corrected/CHANGES.md`, and re-run 7b and 7c.

**7f. Baseline.** Find the matching SigmaHQ rule:
```powershell
# finds SigmaHQ rule files that mention the event ID
Get-ChildItem D:\lab\sigma\rules\windows -Recurse -Filter *.yml | Select-String "1102" | Select-Object -Unique Path
```
Pick the rule whose title matches the technique (for T1059, search `"EncodedCommand"` or `"-enc"` instead of an event ID). Copy it to `rules/sigmahq_baseline/`, run 7b and 7c with it, and record the results.

**Done when:** all three rows for that technique in `results.csv` are filled in.

---

## Step 8: Contamination check (30 min)

For each technique, open a **new** chat and run Prompt 2 from the prompt file. Compare the AI rule, the AI's "from memory" rule, and the real SigmaHQ rule. Fill in `similarity_to_sigmahq` (near-copy / similar logic / different).

---

## Step 9: Write it up (3 h)

1. Fill in the README results table and key findings.
2. Write the report using `report/report_template.md` (2-3 pages).
3. Create a GitHub repo and upload everything **except** `data/` (the `.gitignore` already handles this).

### Upload to GitHub (no command line needed)
github.com → **New repository** → name it `ai-sigma-detection-lab` → Public → Create → **uploading an existing file** → drag in everything except the `data` folder → Commit.

---

## If you get stuck

Copy the exact error message and the command you ran, and send both to me. Don't spend more than 30 minutes stuck on one error.
