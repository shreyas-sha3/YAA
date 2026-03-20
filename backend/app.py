from flask import Flask, request, jsonify, session
from flask_cors import CORS
import requests as req
import time, urllib.parse, re, datetime, html, json
from bs4 import BeautifulSoup
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

CORS(app, supports_credentials=False, origins="*",
     allow_headers=["Content-Type", "X-Session-Token"],
     methods=["GET", "POST", "OPTIONS"])

@app.after_request
def cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Session-Token"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

@app.route("/api/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    return "", 204

# ── Session store keyed by browser session token ──────────────────────────────
_sessions = {}  # token -> {"cookies": list, "headers": dict}

BASE = "https://academia.srmist.edu.in"
PORTAL = f"{BASE}/portal/academia-academic-services/"

def make_http_session(token):
    """Return or create a requests.Session for the given token."""
    if token not in _sessions:
        _sessions[token] = {"cookies": [], "extra_headers": {}}
    s = req.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9", "Connection": "keep-alive"
    })
    
    for c in _sessions[token].get("cookies", []):
        s.cookies.set(c["name"], c["value"], domain=c.get("domain"), path=c.get("path", "/"))
        
    s.headers.update(_sessions[token]["extra_headers"])
    return s

def save_http_session(token, s):
    cookies_list = [
        {"name": c.name, "value": c.value, "domain": c.domain, "path": c.path}
        for c in s.cookies
    ]
    _sessions[token] = {
        "cookies": cookies_list,
        "extra_headers": {k: v for k, v in s.headers.items() if k.lower() in ("x-zcsrf-token", "referer")}
    }

def get_token():
    t = request.headers.get("X-Session-Token") or request.cookies.get("academia_token")
    if not t:
        t = secrets.token_hex(16)
    return t

# ── Auth ────────────────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    email = data.get("email", "").strip()
    password = data.get("password", "")
    token = secrets.token_hex(16)

    if not email.endswith("@srmist.edu.in"):
        email += "@srmist.edu.in"

    s = make_http_session(token)
    try:
        print(f"[1] Fetching CSRF for {email}")

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

        csrf = s.cookies.get('iamcsrcoo') or s.cookies.get('_zcsr_tmp')
        print(f"[1] csrf={csrf}  all_cookies={list(s.cookies.keys())}")

        if not csrf:
            iamcsr = s.cookies.get('iamcsr', '')
            if iamcsr:
                csrf = iamcsr
                print(f"[1] Using iamcsr as csrf fallback: {csrf[:20]}...")

        if not csrf:
            return jsonify({"ok": False, "error": f"Could not get CSRF token. Cookies present: {list(s.cookies.keys())}"}), 401

        s.headers.update({
            "x-zcsrf-token": f"iamcsrcoo={csrf}",
            "Referer": f"{BASE}/",
            "Content-Type": "application/x-www-form-urlencoded"
        })

        lookup_url = f"{BASE}/accounts/p/40-10002227248/signin/v2/lookup/{urllib.parse.quote(email)}"
        print(f"[2] POST lookup")
        res = s.post(lookup_url,
            data={"mode": "primary", "cli_time": str(int(time.time()*1000)), "orgtype": "40"},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        ).json()
        print(f"[2] response keys={list(res.keys())} snippet={str(res)[:300]}")

        lookup = res.get('lookup', {})
        zuid, digest = lookup.get('identifier'), lookup.get('digest')
        if not zuid:
            return jsonify({"ok": False, "error": f"User not found. Response: {str(res)[:300]}"}), 401

        pw_payload = json.dumps({"passwordauth": {"password": password}})
        auth_url = f"{BASE}/accounts/p/40-10002227248/signin/v2/primary/{zuid}/password"
        print(f"[3] POST password auth")
        auth_res = s.post(auth_url,
            params={"digest": digest, "cli_time": str(int(time.time()*1000)), "orgtype": "40"},
            data=pw_payload,
            headers={"Content-Type": "application/json"}
        ).json()
        print(f"[3] auth response keys={list(auth_res.keys())} snippet={str(auth_res)[:300]}")

        next_url = auth_res.get('passwordauth', {}).get('redirect_uri') or auth_res.get('href')

        if auth_res.get('code') == 'SI303' and next_url and 'block-sessions' in next_url:
            print("[3b] Clearing blocked sessions")
            s.delete(f"{BASE}/accounts/p/40-10002227248/webclient/v1/announcement/pre/blocksessions")
            auth_res2 = s.post(auth_url,
                params={"digest": digest, "cli_time": str(int(time.time()*1000)), "orgtype": "40"},
                data=pw_payload,
                headers={"Content-Type": "application/json"}
            ).json()
            print(f"[3b] retry={str(auth_res2)[:200]}")
            next_url = auth_res2.get('passwordauth', {}).get('redirect_uri')

        if not next_url:
            return jsonify({"ok": False, "error": f"No redirect URL. Full auth response: {str(auth_res)[:400]}"}), 401

        if next_url.startswith('/'):
            next_url = BASE + next_url

        print(f"[4] Following redirect: {next_url[:80]}")
        final = s.get(next_url).text
        if "signinFrame" in final:
            return jsonify({"ok": False, "error": "Login failed — still on signin page"}), 401

        save_http_session(token, s)
        print(f"[OK] Login success token={token[:8]}...")
        return jsonify({"ok": True, "token": token})

    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/profile", methods=["GET"])
def profile():
    token = get_token()
    s = make_http_session(token)
    try:
        rec = s.get(f"{PORTAL}report/Student_Profile_Report?urlParams=%7B%7D").json()
        name_field = rec.get("MODEL", {}).get("DATAJSONARRAY", [{}])[0].get("Name", "")
        if " - " in name_field:
            reg, name = name_field.split(" - ", 1)
            return jsonify({"ok": True, "name": name, "reg": reg})
        return jsonify({"ok": True, "name": name_field, "reg": ""})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── Helpers ─────────────────────────────────────────────────────────────────
def get_html(s, url):
    s.headers.update({"X-Requested-With": "XMLHttpRequest"})
    txt = s.get(url).text
    m = re.search(r"pageSanitizer\.sanitize\('(.+?)'\)", txt, re.DOTALL) or \
        re.search(r'zmlvalue="(.+?)"', txt, re.DOTALL)
    if not m:
        return None
    raw = m.group(1)
    try:
        raw = html.unescape(raw).encode('utf-8').decode('unicode_escape')
    except Exception:
        raw = html.unescape(raw)
    return BeautifulSoup(raw, 'html.parser')


def get_academic_planner(s):
    dash = s.get(PORTAL).text
    match = re.search(r'"PAGELINKNAME":"(Academic_Planner_[^"]+)"', dash)
    planner_link = match.group(1) if match else "Academic_Planner_2025_26_EVEN"
    soup = get_html(s, f"{PORTAL}page/{planner_link}")
    if not soup or not soup.find('table'):
        return None, {}

    now = datetime.datetime.now()
    is_even = "EVEN" in planner_link.upper()

    # Determine semester month range and year mapping
    if is_even:
        # Even semester: Jan(0)–Jun(5), columns in blocks of 5
        month_range = range(0, 6)  # block indices
        month_nums = [1, 2, 3, 4, 5, 6]  # actual month numbers
        year_base = now.year
    else:
        # Odd semester: Jul(0)–Dec(5)
        month_range = range(0, 6)
        month_nums = [7, 8, 9, 10, 11, 12]
        year_base = now.year

    calendar_map = {}
    today_do = None
    rows = soup.find('table').find_all('tr')[1:]

    for block_idx in month_range:
        dt_idx = block_idx * 5
        do_idx = block_idx * 5 + 3
        month_num = month_nums[block_idx]

        for row in rows:
            cells = row.find_all('td')
            if len(cells) > do_idx:
                date_val = cells[dt_idx].get_text(strip=True)
                do_val = cells[do_idx].get_text(strip=True)
                if date_val and do_val and do_val.isdigit():
                    try:
                        day = int(date_val)
                        if 1 <= day <= 31:
                            date_key = f"{year_base}-{month_num:02d}-{day:02d}"
                            calendar_map[date_key] = f"Day {do_val}"
                            if day == now.day and month_num == now.month:
                                today_do = f"Day {do_val}"
                    except:
                        pass

    return today_do, calendar_map


# ── Main data endpoint ───────────────────────────────────────────────────────
@app.route("/api/data", methods=["GET"])
def get_data():
    token = get_token()
    s = make_http_session(token)

    try:
        # Timetable
        soup_tt = get_html(s, f"{PORTAL}page/My_Time_Table_2025_26_EVEN") or \
                  get_html(s, f"{PORTAL}page/My_Time_Table_2023_24")
        batch, my_slots = "2", {}

        if soup_tt:
            lbl = soup_tt.find('td', string=re.compile(r'Batch:', re.I))
            batch = "1" if lbl and '1' in lbl.find_next_sibling('td').get_text() else "2"
            for t in soup_tt.find_all('table'):
                tds = t.find_all(['td', 'th'])
                if any('slot' in td.get_text().lower() for td in tds):
                    headers = [td.get_text(strip=True).lower() for td in t.find('tr').find_all(['td', 'th'])]
                    if 'slot' not in headers:
                        continue
                    nc = len(headers)
                    sc = headers.index('slot')
                    tc = 2
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

        # Unified timetable matrix
        suffix = 'Batch_1' if batch == '1' else 'batch_2'
        soup_uni = get_html(s, f"{PORTAL}page/Unified_Time_Table_2025_{suffix}")
        rows = soup_uni.find_all('tr') if soup_uni else []
        times = [td.get_text(strip=True).replace('\t', '') for td in rows[0].find_all('td')[1:]] if rows else []
        matrix = {}
        for r in rows:
            if "Day" in r.get_text():
                cells = r.find_all('td')
                if cells:
                    day_key = cells[0].get_text(strip=True)
                    matrix[day_key] = [td.get_text(strip=True) for td in cells[1:]]

        has_class = [False] * len(times)
        grid = {}
        for day, slots in matrix.items():
            grid[day] = []
            for i, slot_str in enumerate(slots[:len(times)]):
                parts = slot_str.split('/')
                match = None
                for p in parts:
                    p = p.strip()
                    if p in my_slots:
                        match = my_slots[p]
                        break
                if match:
                    has_class[i] = True
                # detect lab: ' / X' multi-slot pattern or L-prefix codes
                is_lab = False
                if ' / ' in slot_str:
                    is_lab = True
                else:
                    clean = slot_str.strip()
                    if re.match(r'^L\d+', clean, re.I):
                        is_lab = True
                grid[day].append({
                    "time": times[i] if i < len(times) else "",
                    "title": match["Title"] if match else None,
                    "room": match["Room"] if match else "",
                    "isLab": is_lab and match is not None,
                    "slots": slot_str
                })
        active_indices = [i for i, v in enumerate(has_class) if v]

        soup_att = get_html(s, f"{PORTAL}page/My_Attendance")
        att, mks, seen_att, seen_mks = [], [], set(), set()
        
        course_titles = {}

        if soup_att:
            for t in soup_att.find_all('table'):
                trows = t.find_all('tr')
                if not trows:
                    continue
                hdr = trows[0].get_text()
                for r in trows[1:]:
                    c = r.find_all('td', recursive=False)
                    if "Attn %" in hdr and len(c) >= 9:
                        code = c[0].get_text(" ", strip=True)
                        title = c[1].get_text(strip=True)
                        
                        # Save the real title to our dictionary
                        course_titles[code] = title
                        
                        if code not in seen_att:
                            seen_att.add(code)
                            
                            conducted_str = c[6].get_text(strip=True) if len(c) > 6 else "0"
                            absent_str = c[7].get_text(strip=True) if len(c) > 7 else "0"
                            attn_pct = c[8].get_text(strip=True) if len(c) > 8 else "0"
                            
                            # FIX: Calculate Attended = Conducted - Absent
                            try:
                                conducted = int(conducted_str)
                                absent = int(absent_str)
                                attended_str = str(conducted - absent)
                            except ValueError:
                                attended_str = "0"
                                
                            att.append({
                                "Title": title,
                                "Conducted": conducted_str,
                                "Attended": attended_str,
                                "Attn": attn_pct
                            })
                    elif "Test Performance" in hdr and len(c) >= 3:
                        code = c[0].get_text(strip=True)
                        if code not in seen_mks:
                            seen_mks.add(code)
                            components = []
                            for td in c[2].find_all('td'):
                                raw = td.get_text(": ", strip=True)
                                m2 = re.match(r'(.+?)/(\d+\.?\d*):\s*(\d+\.?\d*)', raw)
                                if m2:
                                    components.append({
                                        "name": m2.group(1).strip(),
                                        "max": float(m2.group(2)),
                                        "scored": float(m2.group(3))
                                    })
                                elif raw and raw.strip():
                                    components.append({"name": raw, "max": None, "scored": None})
                            if components:
                                category = c[1].get_text(strip=True) if len(c) > 1 else ""
                                
                                # Look up real title: try exact match, then try base code (strip trailing letter)
                                actual_title = course_titles.get(code)
                                if not actual_title:
                                    # Try stripping trailing T/P/J/L suffix (e.g. 21CSE281T -> 21CSE281)
                                    base_code = re.sub(r'[TPJL]$', '', code)
                                    for k, v in course_titles.items():
                                        if k.startswith(base_code) or base_code in k:
                                            actual_title = v
                                            break
                                if not actual_title:
                                    actual_title = code
                                
                                if category and category.lower() in ["theory", "practical", "lab"]:
                                    final_title = f"{actual_title} ({category})"
                                else:
                                    final_title = actual_title
                                    
                                mks.append({"Title": final_title, "Components": components})

        # Academic planner / calendar
        today_do, calendar_map = get_academic_planner(s)

        save_http_session(token, s)

        return jsonify({
            "ok": True,
            "DayOrder": today_do,
            "Schedule": grid,
            "ActiveCols": active_indices,
            "Batch": batch,
            "Attendance": att,
            "Marks": mks,
            "Calendar": calendar_map
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/health", methods=["GET", "HEAD"])
def health_check():
    """
    Lightweight endpoint for UptimeRobot or other monitoring tools.
    Responds to HEAD requests with 200 OK and no body.
    """
    return "", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)