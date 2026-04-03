"""
Firewall Log Analyzer - UPGRADED VERSION
GLA University - Network Security Mini Project
Features: Login, Geolocation Map, Email Alerts, Blacklist, Dark/Light Mode
"""
from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
import os, io, csv, random, re, json, smtplib
from datetime import datetime, timedelta
from collections import Counter
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics import renderPDF
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False

app = Flask(__name__)
app.secret_key = "gla_firewall_2024_secret"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

SUSPICIOUS_PORTS = {22,23,3389,1433,3306,5432,6379,27017,4444,31337,1337,445,135,139}

# In-memory stores
_log_store   = []
_blacklist   = set()
_email_config = {"enabled": False, "smtp": "", "port": 587, "user": "", "password": "", "to": ""}

# Default login credentials
USERS = {"admin": "admin123", "gla": "network2024"}

# ─── IP GEOLOCATION (free api.ip-api.com) ───
import urllib.request

def get_ip_geo(ip):
    try:
        if ip.startswith(("192.168","10.","172.")): 
            return {"country":"Private","lat":20.5937,"lon":78.9629,"city":"Local Network","cc":"IN"}
        url = f"http://ip-api.com/json/{ip}?fields=country,city,lat,lon,countryCode"
        with urllib.request.urlopen(url, timeout=2) as r:
            data = json.loads(r.read())
            return {"country":data.get("country","Unknown"),"city":data.get("city",""),
                    "lat":data.get("lat",0),"lon":data.get("lon",0),"cc":data.get("countryCode","")}
    except:
        return {"country":"Unknown","lat":0,"lon":0,"city":"","cc":""}

def get_geo_for_top_ips(logs, n=15):
    ip_count = Counter(l["src_ip"] for l in logs if l["action"]=="BLOCK")
    results = []
    for ip, count in ip_count.most_common(n):
        geo = get_ip_geo(ip)
        results.append({"ip":ip,"count":count,"lat":geo["lat"],"lon":geo["lon"],
                        "country":geo["country"],"city":geo["city"],"cc":geo["cc"]})
    return results

# ─── SAMPLE DATA ───
def generate_sample_logs(n=800):
    normal_ips  = [f"192.168.{1+i//5}.{10+i*3}" for i in range(15)]
    external_ips= [f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(20)]
    bad_ips     = ["45.33.32.156","185.220.101.42","103.21.244.0","198.199.119.50","91.108.56.130","149.154.167.99","194.165.16.11","89.248.167.131"]
    good_ports  = [80,443,53,8080,8443,25,110,143,21]
    bad_ports   = list(SUSPICIOUS_PORTS)
    protocols   = ["TCP","TCP","TCP","TCP","UDP","UDP","ICMP"]
    interfaces  = ["eth0","eth1","ens3"]
    base = datetime.now() - timedelta(hours=24)
    logs = []
    for _ in range(n):
        is_bad = random.random() < 0.2
        ts = base + timedelta(seconds=random.randint(0, 86400))
        src = random.choice(bad_ips if is_bad else normal_ips+external_ips)
        logs.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip"   : src,
            "dst_ip"   : random.choice(normal_ips[:5]),
            "src_port" : random.randint(1024,65535),
            "dst_port" : random.choice(bad_ports if is_bad else good_ports),
            "protocol" : random.choice(["TCP","TCP","ICMP"] if is_bad else protocols),
            "action"   : ("BLOCK" if random.random()<0.65 else "ALLOW") if is_bad else ("BLOCK" if random.random()<0.12 else "ALLOW"),
            "bytes"    : random.randint(64,65000),
            "interface": random.choice(interfaces),
            "blacklisted": src in _blacklist,
        })
    return sorted(logs, key=lambda x: x["timestamp"])

# ─── PARSER ───
UFW_RE = re.compile(r'(\w{3}\s+\d+\s+\d+:\d+:\d+).*\[UFW\s+(\w+)\].*SRC=(\S+)\s+DST=(\S+).*SPT=(\d+)\s+DPT=(\d+).*PROTO=(\w+)')

def parse_log_text(text):
    lines, parsed = text.strip().splitlines(), []
    for i, line in enumerate(lines):
        line = line.strip()
        if not line: continue
        m = UFW_RE.search(line)
        if m:
            src = m.group(3)
            parsed.append({"timestamp":m.group(1),"src_ip":src,"dst_ip":m.group(4),
                "src_port":int(m.group(5)),"dst_port":int(m.group(6)),"protocol":m.group(7),
                "action":"BLOCK" if "BLOCK" in m.group(2).upper() else "ALLOW",
                "bytes":0,"interface":"eth0","blacklisted":src in _blacklist})
            continue
        if "," in line:
            if i==0 and "timestamp" in line.lower(): continue
            p = [x.strip() for x in line.split(",")]
            if len(p) >= 7:
                try:
                    src = p[1].strip()
                    parsed.append({"timestamp":p[0],"src_ip":src,"dst_ip":p[2],
                        "src_port":int(p[3]),"dst_port":int(p[4]),"protocol":p[5].upper(),
                        "action":p[6].upper(),"bytes":int(p[7]) if len(p)>7 else 0,
                        "interface":p[8] if len(p)>8 else "eth0","blacklisted":src in _blacklist})
                except: pass
    return parsed if parsed else generate_sample_logs(400)

# ─── THREATS ───
def detect_threats(logs):
    ip_blocks, ip_total, ip_ports, ip_icmp = Counter(), Counter(), {}, Counter()
    for l in logs:
        ip_total[l["src_ip"]] += 1
        if l["action"]=="BLOCK": ip_blocks[l["src_ip"]] += 1
        ip_ports.setdefault(l["src_ip"], set()).add(l["dst_port"])
        if l["protocol"]=="ICMP": ip_icmp[l["src_ip"]] += 1
    threats = []
    for ip,ports in ip_ports.items():
        if len(ports)>=12: threats.append({"severity":"HIGH","type":"Port Scan Detected","src_ip":ip,"detail":f"Probed {len(ports)} distinct ports","count":len(ports)})
    for ip,c in ip_blocks.items():
        if c>=8: threats.append({"severity":"HIGH","type":"Brute Force Attempt","src_ip":ip,"detail":f"{c} blocked attempts","count":c})
    susp = {}
    for l in logs:
        if l["dst_port"] in SUSPICIOUS_PORTS and l["action"]=="ALLOW":
            k=f"{l['src_ip']}:{l['dst_port']}"; susp[k]=susp.get(k,0)+1
    for k,c in susp.items():
        ip,port=k.split(":"); threats.append({"severity":"MEDIUM","type":"Suspicious Port Access","src_ip":ip,"detail":f"Port {port} accessed ({c}x)","count":c})
    for ip,c in ip_total.items():
        if c>50: threats.append({"severity":"MEDIUM","type":"High-Volume Traffic","src_ip":ip,"detail":f"{c} total connections","count":c})
    for ip,c in ip_icmp.items():
        if c>=10: threats.append({"severity":"LOW","type":"ICMP Flood/Ping Sweep","src_ip":ip,"detail":f"{c} ICMP packets","count":c})
    # Blacklisted IPs
    bl_ips = set(l["src_ip"] for l in logs if l.get("blacklisted"))
    for ip in bl_ips:
        threats.append({"severity":"HIGH","type":"Blacklisted IP Activity","src_ip":ip,"detail":"IP is on blacklist","count":ip_total[ip]})
    seen,unique=[],[]
    for t in threats:
        k=t["type"]+"|"+t["src_ip"]
        if k not in seen: seen.append(k); unique.append(t)
    return sorted(unique, key=lambda x:{"HIGH":0,"MEDIUM":1,"LOW":2}[x["severity"]])

# ─── ANALYZE ───
def analyze(logs):
    if not logs: return {}
    total=len(logs); blocked=sum(1 for l in logs if l["action"]=="BLOCK")
    hourly={}
    for l in logs:
        h=str(l["timestamp"])[11:13]+":00"; hourly[h]=hourly.get(h,0)+1
    return {
        "total":total,"blocked":blocked,"allowed":total-blocked,
        "block_rate":round(blocked/total*100,1),
        "hourly":hourly,
        "top_src":dict(Counter(l["src_ip"] for l in logs).most_common(8)),
        "protocols":dict(Counter(l["protocol"] for l in logs)),
        "top_ports":{str(k):v for k,v in Counter(l["dst_port"] for l in logs).most_common(8)},
        "actions":dict(Counter(l["action"] for l in logs)),
        "blacklist_count": len(_blacklist),
    }

# ─── EMAIL ALERT ───
def send_email_alert(threats):
    if not _email_config["enabled"] or not _email_config["user"]: return False
    try:
        high = [t for t in threats if t["severity"]=="HIGH"]
        if not high: return False
        msg = MIMEMultipart()
        msg["From"]    = _email_config["user"]
        msg["To"]      = _email_config["to"]
        msg["Subject"] = f"🚨 FIREWALL ALERT — {len(high)} HIGH severity threats detected!"
        body = f"""
FIREWALL LOG ANALYZER — THREAT ALERT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
GLA University Network Security

HIGH SEVERITY THREATS DETECTED: {len(high)}

"""
        for t in high:
            body += f"• {t['type']} from {t['src_ip']} — {t['detail']}\n"
        msg.attach(MIMEText(body, "plain"))
        s = smtplib.SMTP(_email_config["smtp"], _email_config["port"])
        s.starttls()
        s.login(_email_config["user"], _email_config["password"])
        s.send_message(msg)
        s.quit()
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

# ─── AUTH ROUTES ───
@app.route("/login", methods=["GET","POST"])
def login():
    error = ""
    if request.method == "POST":
        u = request.form.get("username","")
        p = request.form.get("password","")
        if USERS.get(u) == p:
            session["user"] = u
            return redirect(url_for("index"))
        error = "Invalid username or password!"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ─── MAIN ROUTES ───
@app.route("/")
@login_required
def index():
    return render_template("index.html", user=session.get("user",""))

@app.route("/api/sample")
@login_required
def api_sample():
    global _log_store
    _log_store = generate_sample_logs(800)
    stats = analyze(_log_store); threats = detect_threats(_log_store)
    if _email_config["enabled"]: send_email_alert(threats)
    return jsonify({**stats,"threats":threats,"threat_count":len(threats),"recent":_log_store[-100:]})

@app.route("/api/upload", methods=["POST"])
@login_required
def api_upload():
    global _log_store
    if "file" not in request.files or not request.files["file"].filename:
        return jsonify({"error":"No file"}), 400
    text = request.files["file"].read().decode("utf-8", errors="ignore")
    _log_store = parse_log_text(text)
    stats = analyze(_log_store); threats = detect_threats(_log_store)
    if _email_config["enabled"]: send_email_alert(threats)
    return jsonify({**stats,"threats":threats,"threat_count":len(threats),"recent":_log_store[-100:]})

@app.route("/api/filter")
@login_required
def api_filter():
    src_ip=request.args.get("src_ip","").lower(); action=request.args.get("action","").upper()
    protocol=request.args.get("protocol","").upper(); port_raw=request.args.get("port","")
    search=request.args.get("search","").lower(); only_bl=request.args.get("blacklisted","")
    page=int(request.args.get("page",0)); per_page=int(request.args.get("per_page",50))
    result=_log_store
    if src_ip:   result=[l for l in result if src_ip in l["src_ip"].lower()]
    if action:   result=[l for l in result if l["action"]==action]
    if protocol: result=[l for l in result if l["protocol"]==protocol]
    if only_bl:  result=[l for l in result if l.get("blacklisted")]
    if port_raw:
        try: p=int(port_raw); result=[l for l in result if l["dst_port"]==p or l["src_port"]==p]
        except: pass
    if search:   result=[l for l in result if any(search in str(v).lower() for v in l.values())]
    total=len(result); sliced=result[page*per_page:(page+1)*per_page]
    return jsonify({"logs":sliced,"total":total,"page":page,"per_page":per_page})

@app.route("/api/blacklist", methods=["GET","POST","DELETE"])
@login_required
def api_blacklist():
    global _blacklist
    if request.method=="GET":
        return jsonify({"blacklist":list(_blacklist)})
    data = request.get_json() or {}
    ip = data.get("ip","").strip()
    if not ip: return jsonify({"error":"No IP"}), 400
    if request.method=="POST":
        _blacklist.add(ip)
        for l in _log_store:
            if l["src_ip"]==ip: l["blacklisted"]=True
        return jsonify({"message":f"{ip} blacklisted","count":len(_blacklist)})
    if request.method=="DELETE":
        _blacklist.discard(ip)
        for l in _log_store:
            if l["src_ip"]==ip: l["blacklisted"]=False
        return jsonify({"message":f"{ip} removed","count":len(_blacklist)})

@app.route("/api/geo")
@login_required
def api_geo():
    data = get_geo_for_top_ips(_log_store, 15)
    return jsonify({"points": data})

@app.route("/api/email_config", methods=["GET","POST"])
@login_required
def api_email_config():
    global _email_config
    if request.method=="POST":
        data = request.get_json() or {}
        _email_config.update(data)
        return jsonify({"message":"Email config saved!","enabled":_email_config["enabled"]})
    return jsonify(_email_config)

@app.route("/api/export/csv")
@login_required
def export_csv():
    if not _log_store: return "No data",400
    buf=io.StringIO(); fields=["timestamp","src_ip","dst_ip","src_port","dst_port","protocol","action","bytes","interface","blacklisted"]
    w=csv.DictWriter(buf,fieldnames=fields,extrasaction="ignore"); w.writeheader(); w.writerows(_log_store)
    buf.seek(0)
    return send_file(io.BytesIO(buf.getvalue().encode()),mimetype="text/csv",as_attachment=True,
                     download_name=f"firewall_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")

@app.route("/api/export/pdf")
@login_required
def export_pdf():
    if not PDF_SUPPORT: return "Install reportlab",500
    if not _log_store: return "No data",400
    stats=analyze(_log_store); threats=detect_threats(_log_store); buf=io.BytesIO()
    doc=SimpleDocTemplate(buf,pagesize=A4,topMargin=30,bottomMargin=30,leftMargin=40,rightMargin=40)
    styles=getSampleStyleSheet(); story=[]
    # Title
    title_style = ParagraphStyle('title',fontName='Helvetica-Bold',fontSize=20,textColor=colors.HexColor("#1a1a2e"),spaceAfter=6)
    story.append(Paragraph("FIREWALL LOG ANALYSIS REPORT", title_style))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  GLA University",styles["Normal"]))
    story.append(Spacer(1,14))
    # Summary
    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    summary=[["Metric","Value"],["Total Events",str(stats["total"])],
             ["Blocked",f"{stats['blocked']} ({stats['block_rate']}%)"],
             ["Allowed",str(stats["allowed"])],["Threats",str(len(threats))],
             ["Blacklisted IPs",str(len(_blacklist))]]
    t=Table(summary,colWidths=[220,220])
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1a1a2e")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f0f4f8")]),
        ("GRID",(0,0),(-1,-1),0.5,colors.grey),("PADDING",(0,0),(-1,-1),8)]))
    story.append(t); story.append(Spacer(1,14))
    # Protocol chart
    if stats.get("protocols"):
        story.append(Paragraph("Protocol Distribution", styles["Heading2"]))
        d=Drawing(200,150)
        pc=Pie(); pc.x=50; pc.y=10; pc.width=100; pc.height=100
        protos=list(stats["protocols"].items())
        pc.data=[v for _,v in protos]; pc.labels=[k for k,_ in protos]
        pc.slices[0].fillColor=colors.HexColor("#60a5fa")
        if len(protos)>1: pc.slices[1].fillColor=colors.HexColor("#e8a030")
        if len(protos)>2: pc.slices[2].fillColor=colors.HexColor("#f05050")
        d.add(pc); story.append(d); story.append(Spacer(1,10))
    # Threats
    if threats:
        story.append(Paragraph(f"Detected Threats ({len(threats)})", styles["Heading2"]))
        rows=[["Severity","Type","Source IP","Detail"]]+[[t["severity"],t["type"],t["src_ip"],t["detail"]] for t in threats[:25]]
        tt=Table(rows,colWidths=[65,140,110,125])
        sev_c={"HIGH":colors.HexColor("#f05050"),"MEDIUM":colors.HexColor("#e8a030"),"LOW":colors.HexColor("#4ade80")}
        ts2=TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1a1a2e")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
            ("GRID",(0,0),(-1,-1),0.5,colors.grey),("PADDING",(0,0),(-1,-1),5)])
        for i,th in enumerate(threats[:25],1):
            ts2.add("TEXTCOLOR",(0,i),(0,i),sev_c.get(th["severity"],colors.black))
            ts2.add("FONTNAME",(0,i),(0,i),"Helvetica-Bold")
        tt.setStyle(ts2); story.append(tt); story.append(Spacer(1,14))
    # Top IPs
    story.append(Paragraph("Top Source IPs", styles["Heading2"]))
    ip_rows=[["IP Address","Connections","Status"]]+[[ip,str(c),"🚫 BLACKLISTED" if ip in _blacklist else "Active"] for ip,c in list(stats["top_src"].items())[:10]]
    it=Table(ip_rows,colWidths=[180,100,160])
    it.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1a1a2e")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f0f4f8")]),
        ("GRID",(0,0),(-1,-1),0.5,colors.grey),("PADDING",(0,0),(-1,-1),6)]))
    story.append(it)
    doc.build(story); buf.seek(0)
    return send_file(buf,mimetype="application/pdf",as_attachment=True,
                     download_name=f"firewall_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")

if __name__=="__main__":
    print("="*50)
    print("  Firewall Log Analyzer v2.0 — GLA University")
    print("  Open: http://127.0.0.1:5000")
    print("  Login: admin / admin123")
    print("="*50)
    app.run(debug=True,port=5000)
