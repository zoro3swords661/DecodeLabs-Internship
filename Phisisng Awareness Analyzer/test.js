/* =========================================================================
   test.js — runs the five Project 3 sample messages through the analyzer
   and checks each verdict. Run with:  node test.js
   ========================================================================= */
const { analyze } = require("./analyzer.js");

const cases = [
  { name: "① CEO wire transfer (BEC)", expect: "Malicious",
    senderRaw: "CEO – STRICTLY CONFIDENTIAL <ceo.urgent@executive-update.com>", claim: "company.com",
    subject: "IMMEDIATE ACTION REQUIRED: Transfer Authorization",
    body: "URGENT: Process the attached wire transfer instruction immediately. This is critical and must remain STRICTLY CONFIDENTIAL. Do not discuss with anyone. Bypass standard procedure.",
    links: [], attachments: [] },

  { name: "② Fake Microsoft alert", expect: "Malicious",
    senderRaw: "Microsoft Support <support@logins-updates.com>", claim: "Microsoft",
    subject: "FW: Urgent: Your Account Security Alert",
    body: "Unusual sign-in detected. Sign in below to secure your account.",
    links: ["https://account.microsoft.com.logins-updates.com/verify"],
    attachments: ["Security_Update_2024.iso"] },

  { name: "③ Lost-wallet SMS", expect: "Suspicious",
    senderRaw: "", claim: "",
    subject: "", body: "I lost my wallet at the airport. Need you to wire transfer funds for my flight immediately. - CEO",
    links: [], attachments: [] },

  { name: "④ Subscription payment failed", expect: "Malicious",
    senderRaw: "ChatGPT Billing <no-reply@chatgpt-billing.net>", claim: "ChatGPT",
    subject: "Urgent: ChatGPT Payment Failure",
    body: "Your subscription payment failed. Update your billing information to avoid service interruption.",
    links: ["bit.ly/secure-billing"], attachments: [] },

  { name: "⑤ Legit Q3 update (control)", expect: "Safe",
    senderRaw: "Project Manager <sarah.lee@company.com>", claim: "company.com",
    subject: "Q3 Project Status Update - Non-Urgent",
    body: "Hi Team, please review the attached project status for Q3 at your earliest convenience. No immediate action is required. Thanks, Sarah.",
    links: [], attachments: ["Q3_Status.pdf"] },
];

let passed = 0;
for (const c of cases) {
  const r = analyze(c);
  const ok = r.verdictLabel === c.expect;
  if (ok) passed++;
  console.log(`\n${ok ? "PASS" : "FAIL"}  ${c.name}`);
  console.log(`      verdict: ${r.verdictLabel} → ${r.action}  (score ${r.score}, expected ${c.expect})`);
  r.flags.forEach(f => console.log(`        [${f.sev.toUpperCase()}] ${f.name}`));
}
console.log(`\n${passed}/${cases.length} cases passed.\n`);
process.exit(passed === cases.length ? 0 : 1);
