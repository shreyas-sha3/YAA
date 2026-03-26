from flask import Flask, request, jsonify, session
from flask_cors import CORS
import requests as req
import time, urllib.parse, re, datetime, html, json
from bs4 import BeautifulSoup
import secrets
import os
from dotenv import load_dotenv
load_dotenv()
from itsdangerous import URLSafeSerializer, BadSignature

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
serializer = URLSafeSerializer(app.secret_key)
creds_serializer = URLSafeSerializer(app.secret_key, salt="creds-auth")

CORS(app, supports_credentials=False, 
     origins=["https://yetanotheracademia.web.app", "http://localhost:5000", "http://127.0.0.1:5000", "http://localhost:5500", "http://127.0.0.1:5500"],
     allow_headers=["Content-Type", "X-Session-Token"],
     methods=["GET", "POST", "OPTIONS"])

BASE = "https://academia.srmist.edu.in"
PORTAL = f"{BASE}/srm_university/academia-academic-services/"

def make_http_session(token):
    s = req.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9", "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin"
    })
    
    if not token:
        return s

    try:
        session_data = serializer.loads(token)
        for c in session_data.get("cookies", []):
            s.cookies.set(c["name"], c["value"], domain=c.get("domain"), path=c.get("path", "/"))
        s.headers.update(session_data.get("extra_headers", {}))
    except (BadSignature, Exception):
        pass

    return s

def save_http_session(s):
    cookies_list = []
    # Retain core IAM, CSRF, and ZALB routing cookies. Drop tracking/analytics cookies.
    for c in s.cookies:
        if "iam" in c.name.lower() or "zcsr" in c.name.lower() or "z_identity" in c.name.lower() or c.name in ("JSESSIONID", "stk", "zccpn", "CT_CSRF_TOKEN") or c.name.startswith("zalb_"):
            cookies_list.append({"name": c.name, "value": c.value, "domain": c.domain, "path": c.path})
            
    session_data = {
        "cookies": cookies_list,
        "extra_headers": {k: v for k, v in s.headers.items() if k.lower() in ("x-zcsrf-token", "referer")}
    }
    return serializer.dumps(session_data)

def get_token():
    t = request.headers.get("X-Session-Token") or request.cookies.get("academia_token")
    return t or ""

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    email = data.get("email", "").strip()
    password = data.get("password", "")
    try:
        token, creds_blob = perform_login(email, password)
        return jsonify({"ok": True, "token": token, "creds": creds_blob})
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 401
    
def perform_login(email, password):
    if not email.endswith("@srmist.edu.in"):
        email += "@srmist.edu.in"

    s = make_http_session("")
    signin_url = f"{BASE}/accounts/p/10002227248/signin?orgtype=40&serviceurl={urllib.parse.quote(PORTAL + 'redirectFromLogin')}"
    resp = s.get(signin_url, allow_redirects=False)
    hops = 0
    while resp.is_redirect and hops < 8:
        loc = resp.headers.get('Location', '')
        if loc.startswith('/'): loc = BASE + loc
        resp = s.get(loc, allow_redirects=False)
        hops += 1
    if resp.is_redirect:
        s.get(resp.headers.get('Location', signin_url))

    csrf = s.cookies.get('iamcsrcoo') or s.cookies.get('_zcsr_tmp') or s.cookies.get('iamcsr')
    if not csrf:
        raise Exception(f"Could not get CSRF token. Cookies: {list(s.cookies.keys())}")

    s.headers.update({
        "x-zcsrf-token": f"iamcsrcoo={csrf}",
        "Referer": f"{BASE}/",
        "Content-Type": "application/x-www-form-urlencoded"
    })

    lookup_url = f"{BASE}/accounts/p/40-10002227248/signin/v2/lookup/{urllib.parse.quote(email)}"
    res = s.post(lookup_url, data={"mode": "primary", "cli_time": str(int(time.time()*1000)), "orgtype": "40"}).json()

    lookup = res.get('lookup', {})
    zuid, digest = lookup.get('identifier'), lookup.get('digest')
    if not zuid:
        raise Exception(f"User not found. Response: {str(res)[:300]}")

    pw_payload = json.dumps({"passwordauth": {"password": password}})
    auth_url = f"{BASE}/accounts/p/40-10002227248/signin/v2/primary/{zuid}/password"
    auth_res = s.post(auth_url, params={"digest": digest, "cli_time": str(int(time.time()*1000)), "orgtype": "40"}, data=pw_payload, headers={"Content-Type": "application/json"}).json()

    next_url = auth_res.get('passwordauth', {}).get('redirect_uri') or auth_res.get('href')

    if auth_res.get('code') == 'SI303' and next_url and 'block-sessions' in next_url:
        s.delete(f"{BASE}/accounts/p/40-10002227248/webclient/v1/announcement/pre/blocksessions")
        auth_res2 = s.post(auth_url, params={"digest": digest, "cli_time": str(int(time.time()*1000)), "orgtype": "40"}, data=pw_payload, headers={"Content-Type": "application/json"}).json()
        next_url = auth_res2.get('passwordauth', {}).get('redirect_uri')

    if not next_url:
        raise Exception(f"No redirect URL. Auth response: {str(auth_res)[:400]}")

    if next_url.startswith('/'): next_url = BASE + next_url

    final = s.get(next_url).text
    if "signinFrame" in final:
        raise Exception("Login failed — still on signin page")

    token = save_http_session(s)
    creds_blob = creds_serializer.dumps({"email": email, "password": password})
    return token, creds_blob


@app.route("/api/autologin", methods=["POST"])
def autologin():
    data = request.json or {}
    creds_blob = data.get("creds", "")
    if not creds_blob:
        return jsonify({"ok": False, "error": "No credentials provided"}), 400

    try:
        creds = creds_serializer.loads(creds_blob)
        email = creds.get("email")
        password = creds.get("password")
        if not email or not password:
            return jsonify({"ok": False, "error": "Invalid credential blob"}), 400
        
        token, new_creds_blob = perform_login(email, password)
        return jsonify({"ok": True, "token": token, "creds": new_creds_blob})
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"ok": False, "error": f"Auto-login failed: {str(e)}"}), 401


@app.route("/api/profile", methods=["GET"])
def profile():
    token = get_token()
    s = make_http_session(token)
    try:
        res = s.get(f"{PORTAL}report/Student_Profile_Report?urlParams=%7B%7D")
        if "signinFrame" in res.text or "accounts/signin" in res.url:
            return jsonify({"ok": False, "error": "SESSION_EXPIRED"}), 401
            
        try:
            rec = res.json()
        except ValueError:
            return jsonify({"ok": False, "error": "SESSION_EXPIRED"}), 401
            
        name_field = rec.get("MODEL", {}).get("DATAJSONARRAY", [{}])[0].get("Name", "")
        if " - " in name_field:
            reg, name = name_field.split(" - ", 1)
            return jsonify({"ok": True, "name": name, "reg": reg})
        return jsonify({"ok": True, "name": name_field, "reg": ""})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

def get_html(s, url):
    s.headers.update({"X-Requested-With": "XMLHttpRequest"})
    txt = s.get(url).text
    m = re.search(r"pageSanitizer\.sanitize\('(.+?)'\)", txt, re.DOTALL) or \
        re.search(r'zmlvalue="(.+?)"', txt, re.DOTALL)
    if not m: return None
    
    raw = m.group(1)
    
    # Python 3.12+ safe string replacement
    raw = raw.replace(r'\x22', '"').replace(r'\x27', "'").replace(r'\/', '/').replace(r'\-', '-').replace(r'\n', '\n').replace(r'\t', '\t')
    raw = html.unescape(raw)
    
    return BeautifulSoup(raw, 'html.parser')

def get_valid_soup(s, candidates):
    """Iterates through possible URLs until one successfully returns parsed HTML."""
    seen = set()
    for link in candidates:
        if link in seen: continue
        seen.add(link)
        soup = get_html(s, f"{PORTAL}page/{link}")
        if soup is not None:
            return soup
    return None

def get_academic_planner(s):
    dash = s.get(PORTAL).text
    match = re.search(r'"PAGELINKNAME":"(Academic_Planner_[^"]+)"', dash)
    planner_link = match.group(1) if match else "Academic_Planner_2025_26_EVEN"
    soup = get_html(s, f"{PORTAL}page/{planner_link}")
    if not soup or not soup.find('table'): return None, {}

    now = datetime.datetime.now()
    month_range, month_nums = (range(0, 6), [1, 2, 3, 4, 5, 6]) if "EVEN" in planner_link.upper() else (range(0, 6), [7, 8, 9, 10, 11, 12])
    year_base = now.year

    calendar_map, today_do = {}, None
    rows = soup.find('table').find_all('tr')

    for block_idx in month_range:
        dt_idx, do_idx, month_num = block_idx * 5, block_idx * 5 + 3, month_nums[block_idx]
        for row in rows:
            cells = row.find_all('td')
            if len(cells) > do_idx:
                date_val, do_val = cells[dt_idx].get_text(strip=True), cells[do_idx].get_text(strip=True)
                if date_val and do_val and do_val.isdigit():
                    try:
                        day = int(date_val)
                        if 1 <= day <= 31:
                            date_key = f"{year_base}-{month_num:02d}-{day:02d}"
                            calendar_map[date_key] = f"Day {do_val}"
                            if day == now.day and month_num == now.month: today_do = f"Day {do_val}"
                    except: pass

    return today_do, calendar_map

@app.route("/api/data", methods=["GET"])
def get_data():
    token = get_token()
    s = make_http_session(token)

    try:
        partial = request.args.get('sync') == 'true'
        batch, my_slots, grid, active_indices = "2", {}, {}, []
        today_do, calendar_map, soup_tt = None, {}, None
        
        dash_html = s.get(PORTAL).text
        
        if not partial:
            # Smart TT Fetch
            tt_matches = re.findall(r'"PAGELINKNAME":"(My_Time_Table_[^"]+)"', dash_html)
            tt_candidates = tt_matches + ["My_Time_Table_2023_24", "My_Time_Table_2025_26_EVEN", "My_Time_Table"]
            soup_tt = get_valid_soup(s, tt_candidates)
            
            if soup_tt is None:
                return jsonify({"ok": False, "error": "SESSION_EXPIRED"}), 401

        if soup_tt:
            lbl = soup_tt.find('td', string=re.compile(r'Batch:', re.I))
            batch = "1" if lbl and '1' in lbl.find_next_sibling('td').get_text() else "2"
            for t in soup_tt.find_all('table'):
                tds = t.find_all(['td', 'th'])
                if any('slot' in td.get_text().lower() for td in tds):
                    headers = [td.get_text(strip=True).lower() for td in t.find('tr').find_all(['td', 'th'])]
                    if 'slot' not in headers: continue
                    nc, sc, tc = len(headers), headers.index('slot'), 2
                    rc = 9 if len(headers) > 9 else len(headers) - 1
                    for i in range(nc, len(tds), nc):
                        chunk = tds[i:i+nc]
                        if len(chunk) >= nc and chunk[tc].get_text(strip=True):
                            for s_str in chunk[sc].get_text(strip=True).strip('-').split('-'):
                                s_str = s_str.strip()
                                if s_str:
                                    my_slots[s_str] = {
                                        "Title": chunk[tc].get_text(strip=True),
                                        "Room": chunk[rc].get_text(strip=True) if rc < len(chunk) else ""
                                    }
                    break
        
        if not partial:
            # Smart Unified TT Fetch
            suffix = 'Batch_1' if batch == '1' else 'batch_2'
            uni_matches = re.findall(r'"PAGELINKNAME":"(Unified_Time_Table_[^"]+)"', dash_html)
            uni_candidates = uni_matches + [f"Unified_Time_Table_2023_24", f"Unified_Time_Table_2025_26_EVEN_{suffix}", f"Unified_Time_Table_2025_{suffix}"]
            soup_uni = get_valid_soup(s, uni_candidates)
        else:
            soup_uni = None
            
        rows = soup_uni.find_all('tr') if soup_uni else []
        times = [td.get_text(strip=True).replace('\t', '') for td in rows[0].find_all('td')[1:]] if rows else []
        matrix = {}
        for r in rows:
            if "Day" in r.get_text():
                cells = r.find_all('td')
                if cells: matrix[cells[0].get_text(strip=True)] = [td.get_text(strip=True) for td in cells[1:]]

        has_class = [False] * len(times)
        for day, slots in matrix.items():
            grid[day] = []
            for i, slot_str in enumerate(slots[:len(times)]):
                parts = slot_str.split('/')
                match = next((my_slots[p.strip()] for p in parts if p.strip() in my_slots), None)
                if match: has_class[i] = True
                is_lab = slot_str.strip().upper().startswith('P') and match is not None
                
                grid[day].append({
                    "time": times[i] if i < len(times) else "",
                    "title": match["Title"] if match else None,
                    "room": match["Room"] if match else "",
                    "isLab": is_lab,
                    "slots": slot_str
                })
        active_indices = [i for i, v in enumerate(has_class) if v]
        
        # Smart Attendance Fetch
        att_matches = re.findall(r'"PAGELINKNAME":"([^"]*Attendance[^"]*)"', dash_html, re.I)
        att_candidates = ["My_Attendance"] + att_matches
        soup_att = get_valid_soup(s, att_candidates)
        
        if soup_att is None:
            return jsonify({"ok": False, "error": "SESSION_EXPIRED"}), 401
            
        att, mks, seen_att, seen_mks = [], [], set(), set()
        course_titles = {}

        if soup_att:
            for t in soup_att.find_all('table'):
                trows = t.find_all('tr')
                if not trows: continue
                hdr = trows[0].get_text()
                for r in trows[1:]:
                    c = r.find_all('td', recursive=False)
                    if "Attn %" in hdr and len(c) >= 9:
                        code_full = c[0].get_text(" ", strip=True)
                        code = code_full.split(" ")[0] if " " in code_full else code_full
                        title, category = c[1].get_text(strip=True), c[2].get_text(strip=True)
                        course_titles[code] = title
                        
                        key = f"{code}_{category}"
                        if key not in seen_att:
                            seen_att.add(key)
                            conducted_str, absent_str, attn_pct = c[6].get_text(strip=True), c[7].get_text(strip=True), c[8].get_text(strip=True)
                            try: attended_str = str(int(conducted_str) - int(absent_str))
                            except ValueError: attended_str = "0"
                                
                            att.append({
                                "Code": code, "Title": title, "Category": category,
                                "Conducted": conducted_str, "Attended": attended_str, "Attn": attn_pct
                            })
                    elif "Test Performance" in hdr and len(c) >= 3:
                        code = c[0].get_text(strip=True)
                        if code not in seen_mks:
                            seen_mks.add(code)
                            components = []
                            for td in c[2].find_all('td'):
                                raw = td.get_text(": ", strip=True)
                                m2 = re.match(r'(.+?)/(\d+\.?\d*):\s*(\d+\.?\d*)', raw)
                                if m2: components.append({"name": m2.group(1).strip(), "max": float(m2.group(2)), "scored": float(m2.group(3))})
                                elif raw and raw.strip(): components.append({"name": raw, "max": None, "scored": None})
                            if components:
                                actual_title = course_titles.get(code)
                                if not actual_title:
                                    base_code = re.sub(r'[TPJL]$', '', code)
                                    for k, v in course_titles.items():
                                        if k.startswith(base_code) or base_code in k:
                                            actual_title = v; break
                                mks.append({"Title": actual_title or code, "Components": components})

        if not partial:
            today_do, calendar_map = get_academic_planner(s)

        if partial:
            return jsonify({"ok": True, "Attendance": att, "Marks": mks})

        return jsonify({
            "ok": True, "DayOrder": today_do, "Schedule": grid,
            "ActiveCols": active_indices, "Batch": batch,
            "Attendance": att, "Marks": mks, "Calendar": calendar_map
        })

    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/health", methods=["GET", "HEAD"])
def health_check():
    return "", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)