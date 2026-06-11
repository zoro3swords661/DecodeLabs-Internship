/* =========================================================================
   Phishing Triage Analyzer — detection engine
   DecodeLabs Project 3. Pure rule-based logic; explainable line by line.
   Each rule maps to a red flag documented in the Project 3 report.
   ========================================================================= */

// ---- helpers -------------------------------------------------------------
const SHORTENERS = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd",
  "buff.ly","rebrand.ly","cutt.ly","rb.gy","shorturl.at","tiny.cc","bl.ink"];
const BAD_EXT = ["iso","js","scr","exe","vbs","jar","bat","cmd","hta","html","htm","lnk","img"];
const FREEMAIL = ["gmail.com","yahoo.com","outlook.com","hotmail.com","proton.me","aol.com","icloud.com"];

// pull an email address out of a "Display Name <addr>" string
function parseSender(raw){
  if(!raw) return {display:"", email:"", domain:""};
  const m = raw.match(/<([^>]+)>/);
  const email = (m ? m[1] : raw).trim().toLowerCase();
  const display = (m ? raw.slice(0, m.index) : "").trim().replace(/^"|"$/g,"");
  const domain = email.includes("@") ? email.split("@")[1] : "";
  return {display, email, domain};
}

// registrable root: last two labels (good enough for triage demo)
function rootDomain(host){
  const parts = host.toLowerCase().replace(/^https?:\/\//,"").split("/")[0].split(".");
  if(parts.length < 2) return host;
  return parts.slice(-2).join(".");
}
function urlHost(u){
  try{ return new URL(u.trim().match(/^https?:\/\//)? u.trim() : "http://"+u.trim()).hostname.toLowerCase(); }
  catch(e){ return u.trim().toLowerCase().replace(/^https?:\/\//,"").split("/")[0]; }
}
function hasNonAscii(s){ return /[^\x00-\x7F]/.test(s); }

// ---- keyword banks (psychology / red-flag language) ----------------------
const KW = {
  urgency:   ["urgent","immediately","immediate action","right away","within 24","expires","expire","asap","act now","final notice","last warning","limited time","before close of business"],
  secrecy:   ["confidential","strictly confidential","do not discuss","keep this between","don't tell","bypass standard","bypass procedure","discreet"],
  authority: ["ceo","cfo","director","it support","help desk","administrator","law enforcement","irs","hr department","payroll"],
  sensitive: ["password","mfa","otp","one-time code","verification code","wire transfer","bank details","billing information","update billing","ssn","credit card","gift card"],
  threat:    ["suspended","locked","account locked","unusual sign-in","unusual activity","unauthorized","legal action","penalty","fine","terminated"],
  reward:    ["congratulations","you have won","prize","gift card","reward","claim now","selected","free"]
};

// negation guards: don't fire when a phrase is explicitly negated
// (e.g. "no immediate action is required", "not urgent", "non-urgent")
const NEGATORS = ["no ","not ","non-","never ","without ","isn't ","doesn't ","no immediate"];
function isNegated(low, kw){
  let i = low.indexOf(kw);
  while(i !== -1){
    const pre = low.slice(Math.max(0, i-16), i);
    if(!NEGATORS.some(n => pre.includes(n))) return false; // at least one un-negated hit
    i = low.indexOf(kw, i+kw.length);
  }
  return true; // every occurrence was negated
}
function findKeywords(text, bank){
  const low = text.toLowerCase();
  return bank.filter(k => low.includes(k) && !isNegated(low, k));
}

// ---- main analyzer -------------------------------------------------------
function analyze(input){
  const {senderRaw, claim, subject, body, links, attachments} = input;
  const s = parseSender(senderRaw);
  const text = `${subject}\n${body}`;
  const flags = [];
  let score = 0;
  const add = (name, why, sev, evidence) => {
    flags.push({name, why, sev, evidence});
    score += sev==="high"?3 : sev==="med"?2 : 1;
  };

  // RF1 — sender / display-name vs domain mismatch
  if(claim && s.domain){
    const claimRoot = rootDomain(claim.includes(".")? claim : claim.replace(/\s+/g,"")+ ".com");
    const claimWord = claim.toLowerCase().replace(/\.[a-z]+$/,"").replace(/[^a-z0-9]/g,"");
    const domainHasClaim = s.domain.replace(/[^a-z0-9]/g,"").includes(claimWord) && claimWord.length>2;
    if(claim.includes(".") ? rootDomain(s.domain)!==claimRoot : !domainHasClaim){
      add("Sender-domain mismatch",
        `The message claims to be from “${claim}” but actually routes from `,
        "high", s.domain || s.email);
    }
  }
  // display name name-drops a brand the domain doesn't match
  if(s.display && s.domain){
    const dn = s.display.toLowerCase();
    const brandWords = ["microsoft","google","paypal","amazon","apple","bank","ceo","it support","chatgpt","openai","netflix"];
    const named = brandWords.find(b => dn.includes(b));
    if(named && !s.domain.replace(/[^a-z]/g,"").includes(named.replace(/[^a-z]/g,""))){
      add("Display-name spoofing",
        `The display name says “${s.display}” but the real address domain doesn’t belong to it: `,
        "high", s.email);
    }
  }
  // freemail sender pretending to be a company
  if(claim && FREEMAIL.includes(s.domain)){
    add("Corporate identity on a free mailbox",
      `A message claiming to be “${claim}” is sent from a free personal mailbox: `,
      "med", s.domain);
  }

  // RF — links: shorteners, lookalike roots, IP, non-ascii, subdomain trap
  (links||[]).filter(Boolean).forEach(rawLink=>{
    const host = urlHost(rawLink);
    const root = rootDomain(host);
    if(SHORTENERS.includes(root)){
      add("Hidden shortened link",
        "A URL shortener conceals the true destination — no root domain to verify: ",
        "high", host);
    }
    if(/^\d{1,3}(\.\d{1,3}){3}$/.test(host)){
      add("Raw IP address link","The link points to a bare IP instead of a named domain: ","high", host);
    }
    if(hasNonAscii(host)){
      add("Homoglyph / non-ASCII domain","The link contains non-standard characters mimicking real letters: ","high", host);
    }
    // subdomain trap: brand appears as a label but isn't the root
    if(claim){
      const cw = claim.toLowerCase().replace(/\.[a-z]+$/,"").replace(/[^a-z0-9]/g,"");
      if(cw.length>2 && host.replace(/[^a-z0-9]/g,"").includes(cw) && !root.includes(cw)){
        add("Deceptive subdomain (read right-to-left)",
          `“${claim}” appears only as a subdomain label; the true root domain is `,
          "high", root);
      }
    }
  });

  // RF4 — dangerous attachments
  (attachments||[]).filter(Boolean).forEach(a=>{
    const ext = a.trim().toLowerCase().split(".").pop();
    if(BAD_EXT.includes(ext)){
      add("Dangerous attachment",
        `Uncommon/executable file type ( .${ext} ) often used to smuggle malware: `,
        "high", a.trim());
    }
  });

  // RF5/6 — psychology & sensitive-info language
  const urg = findKeywords(text, KW.urgency);
  const sec = findKeywords(text, KW.secrecy);
  const sens= findKeywords(text, KW.sensitive);
  const thr = findKeywords(text, KW.threat);
  const rew = findKeywords(text, KW.reward);

  if(urg.length) add("Urgency / time-pressure language",
    "Manufactured urgency pushes the reader to act before thinking. Triggered by: ", "med", urg.join(", "));
  if(sec.length) add("Secrecy / bypass request",
    "Demands for secrecy or to bypass normal procedure isolate the target from verification. Triggered by: ", "high", sec.join(", "));
  if(sens.length) add("Request for sensitive info / payment",
    "Asks for credentials, codes, or money movement over message. Triggered by: ", "high", sens.join(", "));
  if(thr.length) add("Fear / threat language",
    "Threatens loss or penalty to provoke a fear response. Triggered by: ", "med", thr.join(", "));
  if(rew.length) add("Greed / unexpected reward",
    "Promises an unearned reward to lure engagement. Triggered by: ", "low", rew.join(", "));

  // RF7 — activity alert that links straight to login
  if(thr.length && (links||[]).filter(Boolean).length){
    add("Activity alert linking to a login page",
      "An alarmist alert that points directly to a sign-in link rather than advising manual navigation.", "med", "alert + link");
  }
  // RF9 — callback / TOAD: phone number, no links
  const phone = (body||"").match(/(\+?\d[\d ()-]{7,}\d)/);
  if(phone && !(links||[]).filter(Boolean).length && /call|support|subscription|renew|charge|cancel/i.test(body||"")){
    add("Callback scam (TOAD)",
      "No link — only a phone number urging the user to call “support” about a charge: ", "med", phone[1].trim());
  }
  // RF10 — QR prompt
  if(/qr code|scan (the|this|to)|scan to/i.test(text)){
    add("QR-code prompt","Asks the user to scan a QR code, moving them to an unmanaged mobile device.","med","QR request");
  }

  // ---- verdict ----------------------------------------------------------
  const high = flags.filter(f=>f.sev==="high").length;
  // technical spoof evidence = the things that confirm malice on their own
  const TECH = ["Sender-domain mismatch","Display-name spoofing","Deceptive subdomain (read right-to-left)",
                "Hidden shortened link","Dangerous attachment","Raw IP address link",
                "Homoglyph / non-ASCII domain","Secrecy / bypass request"];
  const techHits = flags.filter(f=>TECH.includes(f.name)).length;

  let level, action, rationale;
  if(score===0){
    level="safe"; action="Close";
    rationale="No phishing indicators detected. Sender, links, and language look consistent. Close — verify out-of-band only if anything was unexpected.";
  } else if(techHits>=1 || score>=6){
    level="mal"; action="Block & Escalate";
    rationale="Strong indicators present. Block the sender domain, report through the internal tool, and escalate to the security team. Do not interact.";
  } else {
    level="warn"; action="Warn User";
    rationale="Some indicators present but not conclusive — there is no verifiable sender/domain to confirm a spoof. Warn the user and verify the request through a known, separate channel before any action.";
  }

  return {sender:s, flags, score, level, action, rationale,
          verdictLabel: level==="safe"?"Safe":level==="mal"?"Malicious":"Suspicious"};
}



/* =========================================================================
   UI layer
   ========================================================================= */
if(typeof window !== "undefined"){
  const SAMPLES = [
    {label:"① CEO wire transfer (BEC)", sender:"CEO – STRICTLY CONFIDENTIAL <ceo.urgent@executive-update.com>", claim:"company.com",
     subject:"IMMEDIATE ACTION REQUIRED: Transfer Authorization",
     body:"URGENT: Process the attached wire transfer instruction immediately. This is critical and must remain STRICTLY CONFIDENTIAL. Do not discuss with anyone. Bypass standard procedure. Thank you.",
     links:"", attach:""},
    {label:"② Fake Microsoft alert", sender:"Microsoft Support <support@logins-updates.com>", claim:"Microsoft",
     subject:"FW: Urgent: Your Account Security Alert",
     body:"Unusual sign-in detected on your account. Sign in below to secure your account.",
     links:"https://account.microsoft.com.logins-updates.com/verify", attach:"Security_Update_2024.iso"},
    {label:"③ Lost-wallet SMS", sender:"", claim:"",
     subject:"", body:"I lost my wallet at the airport. Need you to wire transfer funds for my flight immediately. - CEO",
     links:"", attach:""},
    {label:"④ Subscription payment failed", sender:"ChatGPT Billing <no-reply@chatgpt-billing.net>", claim:"ChatGPT",
     subject:"Urgent: ChatGPT Payment Failure",
     body:"Your subscription payment failed. Update your billing information to avoid service interruption.",
     links:"bit.ly/secure-billing", attach:""},
    {label:"⑤ Legit Q3 update (control)", sender:"Project Manager <sarah.lee@company.com>", claim:"company.com",
     subject:"Q3 Project Status Update - Non-Urgent",
     body:"Hi Team, please review the attached project status for Q3 at your earliest convenience. No immediate action is required. Thanks, Sarah.",
     links:"", attach:"Q3_Status.pdf"},
  ];

  const $ = id => document.getElementById(id);
  const esc = s => (s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");

  function collect(){
    return {
      senderRaw: $("sender").value,
      claim: $("claim").value,
      subject: $("subject").value,
      body: $("body").value,
      links: $("links").value.split("\n").map(x=>x.trim()).filter(Boolean),
      attachments: $("attach").value.split("\n").map(x=>x.trim()).filter(Boolean),
    };
  }

  function render(r){
    const sevWord = {high:"High", med:"Medium", low:"Low"};
    let html = "";
    html += `<div class="verdict ${r.level}">
      <div class="vtop">
        <span class="vbadge">${r.verdictLabel}</span>
        <span class="vaction">→ ${esc(r.action)}</span>
        <span class="score"><span class="num">${r.score}</span><span class="lbl">risk score</span></span>
      </div>
      <div class="vrationale">${esc(r.rationale)}</div>
    </div>`;

    if(r.flags.length){
      html += `<div class="sec-label">Red flags identified <span class="ct">— ${r.flags.length} found</span></div>`;
      r.flags.forEach(f=>{
        html += `<div class="flag sev-${f.sev}">
          <div class="fh"><span class="fname">${esc(f.name)}</span><span class="sev">${sevWord[f.sev]}</span></div>
          <div class="fwhy">${esc(f.why)}${f.evidence?`<span class="et">${esc(f.evidence)}</span>`:""}</div>
        </div>`;
      });
    } else {
      html += `<div class="clean">✓ No red flags detected. After a quick sender check this message can be safely closed.</div>`;
    }
    $("result").innerHTML = html;
    $("resHint").textContent = `${r.verdictLabel.toLowerCase()} · ${r.flags.length} flag${r.flags.length===1?"":"s"}`;
  }

  function run(){
    const inp = collect();
    if(!inp.senderRaw && !inp.subject && !inp.body && !inp.links.length){
      $("resHint").textContent = "nothing to analyze";
      return;
    }
    render(analyze(inp));
    $("result").scrollIntoView({behavior:"smooth", block:"nearest"});
  }

  function loadSample(s){
    $("sender").value=s.sender; $("claim").value=s.claim; $("subject").value=s.subject;
    $("body").value=s.body; $("links").value=s.links; $("attach").value=s.attach;
    run();
  }
  function clearAll(){
    ["sender","claim","subject","body","links","attach"].forEach(id=>$(id).value="");
    $("result").innerHTML = document.querySelector(".empty") ? "" : "";
    $("result").innerHTML = `<div class="empty"><div class="big">⌖</div>Enter a message and run <strong>Analyze</strong>, or load a sample.<br>The analyzer inspects the sender, links, attachments, and language,<br>then returns a Close / Warn / Block verdict.</div>`;
    $("resHint").textContent="awaiting input";
  }

  // wire up
  document.addEventListener("DOMContentLoaded", ()=>{
    const chips = $("chips");
    SAMPLES.forEach(s=>{
      const c = document.createElement("button");
      c.className="chip"; c.type="button"; c.textContent=s.label;
      c.onclick=()=>loadSample(s);
      chips.appendChild(c);
    });
    $("run").onclick = run;
    $("clear").onclick = clearAll;
    // allow Ctrl/Cmd+Enter to run from any field
    document.addEventListener("keydown", e=>{
      if((e.ctrlKey||e.metaKey) && e.key==="Enter") run();
    });
  });
}

/* ---- Node.js export (for running test.js outside the browser) ----------- */
if(typeof module !== "undefined" && module.exports){
  module.exports = { analyze, parseSender, rootDomain };
}
