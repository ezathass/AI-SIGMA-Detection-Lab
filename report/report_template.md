# Can AI Write Detection Rules That Work?
### Testing LLM-generated Sigma rules against real attack and benign Windows logs

*Ezat Hassan · INFS 680 · AI Threat Analysis Lab, Option B · [date]*
*GitHub: [link]*

Target length: 2-3 pages. Short paragraphs. Use the results table as the centrepiece.

---

## 1. Objective (1 paragraph)
What question you tested and why it matters. Hint: SOC teams are starting to use AI to write detections. A rule that misses attacks gives false confidence, and a rule that fires on normal activity buries analysts in alerts. So "does it work?" is worth testing before trusting it.

## 2. Setup (bullets)
- Tools: Chainsaw [version], SigmaHQ rules [date downloaded]
- Attack data: EVTX-ATTACK-SAMPLES, [N] files across 3 techniques
- Benign data: my own Security, System, and PowerShell logs ([date range], about [N] events), kept private
- LLM: [model, version], tested [date]
- Safety: no attack tools were run. Only published log samples were used.

## 3. Method (short numbered list)
Generate → test on attack logs → test on benign logs → score → correct → compare to SigmaHQ → contamination check. One sentence each.

## 4. Results
Paste the results table. Then 2-3 sentences on the overall pattern.

## 5. What the AI got wrong, and how I found it
The most important section. 2-4 concrete examples from `CHANGES.md`, e.g.:
> "The AI's T1059 rule only matched `-EncodedCommand`. It missed the short form `-enc` used in [sample file]. I found this because the rule caught 1 of 3 attack files."

## 6. Contamination check
Were the AI rules near-copies of SigmaHQ rules? What does that mean? (If it's copying public rules, it may do fine on well-known techniques and badly on new ones.)

## 7. What did AI actually add?
Be honest: did it save time? Did it produce a usable first draft? Would you trust it without testing? (The expected answer: useful for a first draft, not trustworthy without testing.)

## 8. Limitations
Small sample, one model, lab-recorded attack data, benign logs from one laptop.

## 9. Conclusion (2-3 sentences)
Answer the research question directly.
