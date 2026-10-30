---
version: 1
slug: "painel-src-app-tsx"
primary_target: "painel/src/App.tsx"
related_targets: ["painel/index.html"]
---

# Surface brief: painel de triagem

Scope: painel/ (Vite + React + TypeScript). Visitor mode: Operate.
Audience and job: SOC tier-1 analyst clearing a queue of Wazuh alerts; secondary, portfolio reviewers.
Task: read the alert, its untrusted evidence and IP reputation, request the AI analysis on demand, compare AI vs final suggestion and policy adjustments, decide (approve / correct with note / discard with note), next. Feedback items view with release from quarantine.
Constraints: PT/EN switch; untrusted text rendered inert; analysis only on button press (quota); reputation lookups only when cached or on request; keyboard path J/K/A/C/D.

## Direction contract

THESIS: The alert queue is a rack of control strips: each alert is a strip with fixed fields, and deciding moves the strip between bays under a stamp. It refuses the SIEM default of a blue table plus a flyout of rounded cards.

OWN-WORLD: An operations room at night. Petrol ground #13202A, bays #16252F and #1B2D3A, strips in buff #E6D9B8 with ink #1B242B, a level designator block on a fixed magnitude ramp, amber #F0A43A for focus only. Flat colour with no glow, gradient or glass, square corners, 1px rules. B612 for everything and B612 Mono for tabular figures and logs. Approvals and corrections get blue stamps; a discard gets an oxblood stamp (#7A3B34) so a discarded alert reads apart from accepted ones at a glance. Overridden values are struck through, never removed.

STORY: The analyst scans the rack, opens the top strip, reads the evidence and reputation, asks for the analysis, compares AI and final values on the key rail, decides with one key, and watches the strip slide into Decided.

FIRST VIEWPORT: A 56px bar (brand, Queue/Feedback tabs, search, API status, PT/EN). Left, a 600px rack with the Pending bay above the Decided bay. Right, the open alert: large designator, title and meta, then Evidence beside Reputation, the AI vs final twin columns around Classification, Severity and Action, and the adjustments. A fixed decision bar at the bottom: Approve as primary, then Correct, Discard and Next.

FORM: Control strips, candidate 7 of 7 on the ordered list; seed:3e4f4b76c8a9ec8d. Signature move: the decided strip slides from Pending into Decided and receives its stamp.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
