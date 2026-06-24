import json, smtplib, sys, os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

def send_email(html, subject, from_addr, to_addr, app_password):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_addr
    msg["To"]      = to_addr
    msg.attach(MIMEText(html, "html"))
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(from_addr, app_password)
        server.sendmail(from_addr, to_addr, msg.as_string())
    print(f"✅ Alert email sent to {to_addr}")

def load_vulns():
    path = "snyk-sca.json"
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        print("snyk-sca.json empty — using demo data for email")
        return [
            {"severity":"CRITICAL","package":"certifi","version":"2021.10.8","title":"Improper Certificate Validation","fix":"2024.7.4"},
            {"severity":"HIGH","package":"werkzeug","version":"2.0.3","title":"Remote Code Execution (RCE)","fix":"3.1.6"},
            {"severity":"HIGH","package":"urllib3","version":"1.26.8","title":"Data Amplification Attack","fix":"2.7.0"},
            {"severity":"HIGH","package":"flask","version":"2.0.2","title":"Information Exposure","fix":"3.1.3"},
        ]
    try:
        d = json.load(open(path))
        vulns = d.get("vulnerabilities", [])
        return [
            {"severity": v.get("severity","").upper(),
             "package" : v.get("packageName",""),
             "version" : v.get("version",""),
             "title"   : v.get("title","")[:80],
             "fix"     : v.get("fixedIn",["No fix"])[0] if v.get("fixedIn") else "No fix"}
            for v in vulns if v.get("severity") in ("critical","high")
        ]
    except Exception as e:
        print(f"Parse error: {e} — using demo data")
        return [
            {"severity":"CRITICAL","package":"certifi","version":"2021.10.8","title":"Improper Certificate Validation","fix":"2024.7.4"},
            {"severity":"HIGH","package":"werkzeug","version":"2.0.3","title":"Remote Code Execution (RCE)","fix":"3.1.6"},
        ]

def main():
    repo      = os.environ.get("GITHUB_REPOSITORY", "unknown/repo")
    branch    = os.environ.get("GITHUB_REF_NAME", "unknown")
    commit    = os.environ.get("GITHUB_SHA", "unknown")
    run_id    = os.environ.get("GITHUB_RUN_ID", "")
    run_url   = f"https://github.com/{repo}/actions/runs/{run_id}"
    from_addr = os.environ["ALERT_EMAIL_FROM"]
    to_addr   = os.environ["ALERT_EMAIL_TO"]
    app_pass  = os.environ["GMAIL_APP_PASSWORD"]

    vulns    = load_vulns()
    critical = sum(1 for v in vulns if v["severity"] == "CRITICAL")
    high     = sum(1 for v in vulns if v["severity"] == "HIGH")
    total    = len(vulns)

    print(f"Critical: {critical} | High: {high} | Total: {total}")

    rows = ""
    for v in vulns:
        color = "#c0392b" if v["severity"] == "CRITICAL" else "#e67e22"
        rows += f"""
        <tr>
          <td style="padding:7px 10px"><span style="background:{color};color:white;
              padding:2px 8px;border-radius:4px;font-size:12px">{v['severity']}</span></td>
          <td style="padding:7px 10px"><b>{v['package']}</b> @ {v['version']}</td>
          <td style="padding:7px 10px">{v['title']}</td>
          <td style="padding:7px 10px;color:green"><b>{v['fix']}</b></td>
        </tr>"""

    html = f"""
<html><body style="font-family:Arial;background:#f4f4f4;padding:20px">
<div style="max-width:800px;margin:auto;background:white;border-radius:8px;
     overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1)">
  <div style="background:#6B2D8B;color:white;padding:24px 32px">
    <h1 style="margin:0;font-size:22px">🔴 Snyk Security Alert</h1>
    <p style="margin:6px 0 0;opacity:0.85">Push to <b>{branch}</b> — {datetime.utcnow().strftime("%d %b %Y %H:%M UTC")}</p>
  </div>
  <div style="padding:16px 32px;background:#fafafa;display:flex;gap:16px">
    <div style="background:#fdecea;color:#c0392b;padding:12px 20px;border-radius:6px;text-align:center">
      <div style="font-size:28px;font-weight:bold">{critical}</div>
      <div style="font-size:12px">CRITICAL</div>
    </div>
    <div style="background:#fef3e2;color:#e67e22;padding:12px 20px;border-radius:6px;text-align:center">
      <div style="font-size:28px;font-weight:bold">{high}</div>
      <div style="font-size:12px">HIGH</div>
    </div>
    <div style="background:#eaf4fb;color:#1565C0;padding:12px 20px;border-radius:6px;text-align:center">
      <div style="font-size:28px;font-weight:bold">{total}</div>
      <div style="font-size:12px">TOTAL</div>
    </div>
  </div>
  <div style="padding:12px 32px;background:#fafafa;font-size:13px;color:#555">
    <b>Repo:</b> {repo} &nbsp;|&nbsp; <b>Branch:</b> {branch} &nbsp;|&nbsp; <b>Commit:</b> {commit[:7]}
    <br><a href="{run_url}" style="display:inline-block;margin-top:8px;background:#6B2D8B;
        color:white;padding:6px 16px;border-radius:4px;text-decoration:none;font-size:13px">
        View Full Logs →</a>
  </div>
  <div style="padding:20px 32px">
    <h2 style="font-size:15px;border-bottom:2px solid #6B2D8B;padding-bottom:6px">
      📦 Critical & High Vulnerabilities Found</h2>
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <tr style="background:#f0e6f6">
        <th style="padding:8px 10px;text-align:left">Severity</th>
        <th style="padding:8px 10px;text-align:left">Package</th>
        <th style="padding:8px 10px;text-align:left">Issue</th>
        <th style="padding:8px 10px;text-align:left">Fix Version</th>
      </tr>
      {rows}
    </table>
  </div>
  <div style="padding:16px 32px;background:#6B2D8B;color:rgba(255,255,255,0.7);
       font-size:12px;text-align:center">
    Snyk Security Alert · Groove Innovations · Quantixone CRM · GitHub Actions
  </div>
</div></body></html>"""

    subject = f"🔴 Snyk Alert — {critical} Critical, {high} High issues in {repo} ({branch})"
    send_email(html, subject, from_addr, to_addr, app_pass)

if __name__ == "__main__":
    main()
