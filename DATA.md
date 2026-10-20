# Data

Raw logs live in a local `data/` folder that is **never uploaded** (`.gitignore` excludes it). This file documents what was in it.

| Folder | Contents | Source |
|---|---|---|
| `attack/T1070/` | Attack sample .evtx files with log clearing (1102 / 104) | EVTX-ATTACK-SAMPLES |
| `attack/T1136/` | Attack samples with account creation / admin group add (4720 / 4732) | EVTX-ATTACK-SAMPLES |
| `attack/T1059/` | Attack samples with encoded PowerShell | EVTX-ATTACK-SAMPLES |
| `benign/` | My own exported Windows logs (normal activity) | My laptop |

**Why the benign logs stay private:** they contain my username, computer name, and activity history. Publishing your own logs is exactly the kind of data leak this course warns about. In the report, describe them (date range, number of events, which logs) without sharing them.

In the README, list the exact attack sample file names you used, so anyone can download the same ones.
