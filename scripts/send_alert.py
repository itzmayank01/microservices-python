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

def main():
    repo      = os.environ.get("GITHUB_REPOSITORY", "unknown/repo")
    branch    = os.environ.get("GITHUB_REF_NAME", "unknown")
    commit    = os.environ.get("GITHUB_SHA", "unknown")
    run_id    = os.environ.get("GITHUB_RUN_ID", "")
    run_url   = f"https://github.com/{repo}/actions/runs/{run_id}"
    from_addr = os.environ["ALERT_EMAIL_FROM"]
    to_addr   = os.environ["ALERT_EMAIL_TO"]
    app_pass  = os.environ["GMAIL_APP_PASSWORD"]

    # Load SCA report
    vulns = []
    if os.path.exists("snyk-sca.json"):
        d = json.load(open("snyk-sca.json"))
        for v in d.get("vulnerabilities", []):
            if v.get("severity") in ("critical", "high"):
                vulns.append({
                    "severity": v.get("severity","").upper(),
                    "package" : v.get("packageName",""),
                    "version" : v.get("version",""),
                    "title"   : v.get("title","")[:80],
                    "fix"     : v.get("fixedIn",["No fix"])[0] if v.get("fixedIn") else "No fix"
                })

    total    = len(vulns)
    critical = sum(1 for v in vulns if v["severity"] == "CRITICAL")
    high     = sum(1 for v in vulns if v["severity"] == "HIGH")

    print(f"Critical: {critical} | High: {high} | Total: {total}")

    if total == 0:
        print("✅ No Critical/High issues — no email sent.")
        return

    rows = ""
    for v in vulns[:20]:
        color = "#c0392b" if v["severity"] == "CRITICAL" else "#e67e22"
        rows += f"""
        <tr>
          <td><span style="background:{color};color:white;padding:2px 8px;
              border-radius:4px;font-size:12px">{v['severity']}</span></td>
          <td><b>{v['package']}</b> @ {v['version']}</td>
          <td>{v['title']}</td>
          <td style="color:green"><b>{v['fix']}</b></td>
        </tr>"""

    html = f"""
<html><body style="font-family:Arial;background:#f4f4f4;padding:20px">
<div style="max-width:800px;margin:auto;background:white;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1)">
  <div style="background:#6B2D8B;color:white;padding:24px 32px">
    <h1 style="margin:0;font-size:22px">🔴 Snyk Security Alert</h1>
    <p style="margin:6px 0 0;opacity:0.85">Scan triggered on push to <b>{branch}</b> — {datetime.utcnow().strftime("%d %b %Y %H:%M UTC")}</p>
  </div>
  <div style="padding:16px 32px;background:#fafafa;display:flex;gap:20px">
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
  <div style="padding:12px 32px;background:#fafafa;font-size:13px;color:#666">
    <span style="margin-right:20px">📁 <b>{repo}</b></span>
    <span style="margin-right:20px">🌿 <b>{branch}</b></span>
    <span>🔖 <b>{commit[:7]}</b></span>
    <br><a href="{run_url}" style="display:inline-block;margin-top:8px;background:#6B2D8B;color:white;padding:6px 16px;border-radius:4px;text-decoration:none;font-size:13px">View Full Logs →</a>
  </div>
  <div style="padding:20px 32px">
    <h2 style="font-size:15px;border-bottom:2px solid #6B2D8B;padding-bottom:6px">📦 Critical & High Vulnerabilities</h2>
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <tr style="background:#f0e6f6">
        <th style="padding:8px;text-align:left">Severity</th>
        <th style="padding:8px;text-align:left">Package</th>
        <th style="padding:8px;text-align:left">Issue</th>
        <th style="padding:8px;text-align:left">Fix Version</th>
      </tr>
      {rows}
    </table>
  </div>
  <div style="padding:16px 32px;background:#6B2D8B;color:rgba(255,255,255,0.7);font-size:12px;text-align:center">
    Snyk Security Alert · Groove Innovations · Quantixone CRM · GitHub Actions
  </div>
</div>
</body></html>"""

    subject = f"🔴 Snyk Alert — {critical} Critical, {high} High issues in {repo} ({branch})"
    send_email(html, subject, from_addr, to_addr, app_pass)

if __name__ == "__main__":
    main()
