# Phishing Triage Analyzer

**DecodeLabs · Cyber Security · Project 3 — Phishing Awareness Analysis**

A browser-based tool that analyzes an email or message, lists the red flags it
finds, explains why each is unsafe, and returns a triage verdict:
**Safe → Close**, **Suspicious → Warn User**, or **Malicious → Block & Escalate**.

It implements the analysis documented in the Project 3 report: identify
suspicious links/keywords, list red flags, and explain why a message is unsafe.

---

## How to run

### Option A — just open it (no tools needed)
Double-click `index.html`, or right-click it in VS Code and choose
**"Open with Live Server"** (or "Reveal in File Explorer" → open in a browser).
Everything runs locally in the browser; no internet connection is required.

### Option B — VS Code Live Server (recommended for editing)
1. Open this folder in VS Code (`File → Open Folder`).
2. Install the **Live Server** extension (by Ritwick Dey) if you don't have it.
3. Right-click `index.html` → **Open with Live Server**.
4. The tool opens in your browser and reloads automatically as you edit.

### Option C — run the logic tests (Node.js)
If you have Node.js installed:
```bash
node test.js
```
This runs the five sample messages through the detection engine and checks
each verdict. Expected output: `5/5 cases passed.`

---

## Files

| File | What it is |
|------|------------|
| `index.html`  | The page structure (form, result panel, triage legend). |
| `styles.css`  | All styling — the security-dashboard look. |
| `analyzer.js` | The detection engine **and** the UI wiring. This is the core logic. |
| `test.js`     | Node test harness that verifies the five sample verdicts. |
| `README.md`   | This file. |

---

## How the detection works

`analyzer.js` is a transparent, rule-based engine — no machine learning, no
hidden data. It analyzes whatever message you paste in. Each rule maps to a
red flag from the report:

1. **Sender / display-name mismatch** — compares the real address domain against
   the brand the message claims to be from, and against a name-dropped brand in
   the display name.
2. **URL analysis (right-to-left)** — extracts the true root domain of each link
   (the part before the first single slash) and flags it when a trusted brand
   appears only as a subdomain label (the "subdomain trap").
3. **URL shorteners** — flags links that hide their destination (bit.ly, tinyurl, …).
4. **Dangerous attachments** — flags risky extensions (.iso, .js, .scr, .exe, .html …).
5. **Psychological triggers** — keyword banks for urgency, secrecy/bypass,
   authority, sensitive-info/payment requests, fear, and greed — with negation
   handling so "no immediate action required" does **not** false-trigger.
6. **Combined patterns** — e.g. an alarmist alert that links straight to a login
   page, or a callback (TOAD) scam with a phone number and no link.

### Verdict logic
- Any **technical spoof indicator** (domain mismatch, subdomain trap, shortener,
  dangerous attachment, secrecy/bypass) **or** a total risk score ≥ 6 → **Malicious**.
- Softer indicators with no verifiable spoof → **Suspicious**.
- No indicators → **Safe**.

---

## Note on the sample data

The five loadable samples are **illustrative examples** reconstructed from the
attack types shown in the Project 3 brief (BEC wire transfer, spoofed Microsoft
alert, smishing, SaaS payment lure, and a legitimate control message). They are
provided so the analyzer can be demonstrated live. The tool does **not** contain
a database of real intercepted emails — it analyzes whatever the user enters.

---

## Golden rule

**Pause · Verify · Report.** Recognize the trigger, confirm through a known
out-of-band channel, and report rather than delete.
