# Narration Script — NEX (3:00)

Word-for-word VO with on-screen cues. ~400 words; pace calmly, let the demo breathe.
`[ACTION]` = what you do on screen. `[HOLD]` = pause on the visual.

---

**[0:00] [ON SCREEN: Coverage dashboard, already populated — 6 techniques, 354 events]**

> Every security team has blind spots in its detections — attacks they're not watching for. And the problem is, you can't see what you're not detecting. Finding those gaps is slow, manual work.

**[0:18] [ACTION: hover the "Blind spots" KPI, then move to Run sweep]**

> This is NEX. It's an autonomous purple-team for Splunk. One click, and it attacks your own data the way an attacker would — to find the gap before they do.

**[0:30] [ACTION: click "Run sweep". Agent activity starts streaming]**

> Watch the agent work. This is all running live against a real Splunk instance.

**[0:38] [ON SCREEN: activity stream — enumerate_coverage, map_attack_surface]**

> First it does recon — enumerating what's in the environment and which detections already exist.

**[0:50] [ON SCREEN: the model's hypothesis text naming T1537; graph node turns red]**

> Then the reasoning. This is Foundation-Sec — an open-weights security model, running locally. It picks the highest-impact blind spot: T1537, data exfiltration to a cloud account — three hundred and one events, and nothing watching for it.

**[1:20] [ON SCREEN: test_detection → 301 hits, 0 detections; EXPOSED banner]**

> It doesn't guess — it proves it. It runs the search: three hundred one malicious events, zero detections covering them.

**[1:38] [ON SCREEN: skeptic step]**

> Then it argues with itself — a skeptic pass that checks the real detection list to make sure it isn't crying wolf. Confirmed: this gap is real.

**[2:00] [ON SCREEN: Authored detection panel fills with SPL + Sigma]**

> So it writes the fix itself — a Splunk detection, and a portable Sigma rule.

**[2:12] [ACTION/ON SCREEN: deploy_detection; coverage 0→1; banner turns green; node flips red→green]**

> And it deploys it — as a real saved search in Splunk. Coverage goes from zero to one. **[HOLD 2s on the green flip.]** The blind spot is closed.

**[2:38] [ACTION: click "Detections" in the sidebar]**

> And it's real — there's the detection NEX just authored, sitting right next to the team's existing rules.

**[2:50] [ON SCREEN: end card / stack]**

> Found, proved, fixed, and verified — autonomously, in under a minute. That's agentic security operations. NEX — built on Splunk, the Splunk MCP Server, Foundation-Sec, and MITRE ATT&CK.

**[3:00] END**

---

## Delivery tips
- Land hard on **"three hundred one events, zero detections"** and **"zero to one."** Those two numbers carry the proof.
- Slow down for the green flip — silence for ~1s is fine; the visual does the work.
- If asked about realism on the form: "The blind spot is a controlled scenario like a CTF range, but the mechanism is fully real — point it at any data and it finds genuine gaps."
