import base64
import datetime
import html
import json
import os
import random
import re
import secrets
import time
import urllib.parse

import requests as req
from bs4 import BeautifulSoup
from flask import Flask, jsonify, request
from flask_cors import CORS
from itsdangerous import URLSafeSerializer

try:
    from dotenv import load_dotenv

    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
except ImportError:
    pass

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
serializer = URLSafeSerializer(app.secret_key)
CORS(
    app,
    supports_credentials=False,
    origins=[
        "https://yetanotheracademia.web.app",
        "http://localhost:5000",
        "http://127.0.0.1:5000",
        "http://localhost:5500",
        "*",
    ],
    allow_headers=["Content-Type", "X-Session-Token"],
    methods=["GET", "POST", "OPTIONS"],
)

# ==========================================
# CONFIGURATION & CONSTANTS
# ==========================================
STUDENT_PORTAL_URL = "https://sp.srmist.edu.in/srmiststudentportal"
ACADEMIA_BASE_URL = "https://academia.srmist.edu.in"
ACADEMIA_PORTAL_URL = f"{ACADEMIA_BASE_URL}/srm_university/academia-academic-services/"
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"


# ==========================================
# TIME HELPER - SINGAPORE TIME SIMULATION
# ==========================================
def get_sgt_now():
    """Returns current datetime explicitly shifted to Singapore Time (UTC+8)"""
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    sgt_offset = datetime.timedelta(hours=8)
    return utc_now + sgt_offset


# ==========================================
# SESSION MANAGEMENT UTILITIES
# ==========================================
def make_session(token=None):
    s = req.Session()
    s.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-GB,en;q=0.9",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
    )
    if token:
        try:
            sd = serializer.loads(token)
            for c in sd.get("cookies", []):
                if c.get("domain"):
                    s.cookies.set(
                        c["name"],
                        c["value"],
                        domain=c["domain"],
                        path=c.get("path", "/"),
                    )
                else:
                    s.cookies.set(c["name"], c["value"], path=c.get("path", "/"))
        except Exception:
            pass
    return s


def save_session(s, extra=None):
    sd = {
        "cookies": [
            {"name": c.name, "value": c.value, "domain": c.domain, "path": c.path}
            for c in s.cookies
        ]
    }
    if extra:
        sd["extra"] = extra
    return serializer.dumps(sd)


def generate_telemetry(ulen, plen, now_ms, top_ms):
    return {
        "startTime": now_ms - top_ms,
        "currentDomain": "sp.srmist.edu.in",
        "timezoneOffset": -480,  # <-- explicitly set to Singapore browser offset
        "screenWidth": 1920,
        "screenHeight": 1080,
        "colorDepth": 24,
        "devicePixelRatio": 1.5,
        "platform": "Linux x86_64",
        "userAgent": USER_AGENT,
        "language": "en-GB",
        "hardwareConcurrency": 16,
        "deviceMemory": 8,
        "touchSupport": False,
        "webdriver": False,
        "mouseClicks": random.randint(2, 6),
        "mouseMovements": random.randint(10, 40),
        "keystrokeCount": ulen + plen + random.randint(2, 5),
        "typingSpeedMs": max(1000, top_ms - random.randint(1000, 3000)),
        "canvasHash": "-863698a",
        "submitTime": now_ms,
        "timeOnPageMs": top_ms,
    }


# ==========================================
# PORTAL 1: ACADEMIA ZOHO LOGIN
# ==========================================
def authenticate_academia_portal(s, email, password):
    signin_url = f"{ACADEMIA_BASE_URL}/accounts/p/10002227248/signin?orgtype=40&serviceurl={urllib.parse.quote(ACADEMIA_PORTAL_URL + 'redirectFromLogin')}"
    resp = s.get(signin_url, allow_redirects=False)
    hops = 0
    while resp.is_redirect and hops < 8:
        loc = resp.headers.get("Location", "")
        if loc.startswith("/"):
            loc = ACADEMIA_BASE_URL + loc
        resp = s.get(loc, allow_redirects=False)
        hops += 1
    if resp.is_redirect:
        s.get(resp.headers.get("Location", signin_url))

    csrf = (
        s.cookies.get("iamcsrcoo", domain=".srmist.edu.in")
        or s.cookies.get("_zcsr_tmp")
        or s.cookies.get("iamcsr")
    )
    zoho_headers = {
        "x-zcsrf-token": f"iamcsrcoo={csrf}",
        "Referer": f"{ACADEMIA_BASE_URL}/",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    lookup_url = f"{ACADEMIA_BASE_URL}/accounts/p/40-10002227248/signin/v2/lookup/{urllib.parse.quote(email)}"
    res = s.post(
        lookup_url,
        data={
            "mode": "primary",
            "cli_time": str(int(get_sgt_now().timestamp() * 1000)),
            "orgtype": "40",
        },
        headers=zoho_headers,
    ).json()
    zuid, digest = (
        res.get("lookup", {}).get("identifier"),
        res.get("lookup", {}).get("digest"),
    )

    pw_payload = json.dumps({"passwordauth": {"password": password}})
    auth_url = f"{ACADEMIA_BASE_URL}/accounts/p/40-10002227248/signin/v2/primary/{zuid}/password"
    zoho_headers["Content-Type"] = "application/json"

    auth_res = s.post(
        auth_url,
        params={
            "digest": digest,
            "cli_time": str(int(get_sgt_now().timestamp() * 1000)),
            "orgtype": "40",
        },
        data=pw_payload,
        headers=zoho_headers,
    ).json()
    next_url = auth_res.get("passwordauth", {}).get("redirect_uri") or auth_res.get(
        "href"
    )

    if auth_res.get("code") == "SI303" and next_url and "block-sessions" in next_url:
        s.delete(
            f"{ACADEMIA_BASE_URL}/accounts/p/40-10002227248/webclient/v1/announcement/pre/blocksessions",
            headers=zoho_headers,
        )
        auth_res = s.post(
            auth_url,
            params={
                "digest": digest,
                "cli_time": str(int(get_sgt_now().timestamp() * 1000)),
                "orgtype": "40",
            },
            data=pw_payload,
            headers=zoho_headers,
        ).json()
        next_url = auth_res.get("passwordauth", {}).get("redirect_uri")

    if next_url and next_url.startswith("/"):
        next_url = ACADEMIA_BASE_URL + next_url
    if next_url:
        s.get(next_url)
    return s


# ==========================================
# PORTAL 2: STUDENT PORTAL ENDPOINTS
# ==========================================
@app.route("/api/login/init", methods=["GET"])
def init_login():
    try:
        s, hi = make_session(), {}
        login_url = f"{STUDENT_PORTAL_URL}/students/loginManager/youLogin.jsp"
        res = s.get(login_url, timeout=15)
        soup = BeautifulSoup(res.text, "html.parser")

        for i in soup.find_all("input"):
            n, id_, v = (
                i.get("name"),
                i.get("id", "").strip().strip('"'),
                i.get("value", ""),
            )
            if n and n.startswith("ph_"):
                hi[n] = v
            elif not n and id_ in ("challengeId", "fpNonce", "dname"):
                hi[id_] = v

        sc = {
            k: m.group(1)
            for k in [
                "domainFieldName",
                "captchaFieldName",
                "randomDelimiter",
                "nonce",
                "b64Url",
                "b64Hosts",
                "captchaText",
            ]
            if (
                m := re.search(
                    rf"['\"]?{k}['\"]?\s*[:=]\s*['\"]([^'\"]+)['\"]", res.text
                )
            )
        }

        captcha_data_uri = ""
        cap_match = re.search(
            r'<img[^>]+id=["\']secure_captcha["\'][^>]+data-src=["\']([^"\']+)',
            res.text,
            re.I,
        )
        if cap_match and sc.get("nonce"):
            captcha_endpoint = cap_match.group(1)
            captcha_url = (
                f"https://sp.srmist.edu.in{captcha_endpoint}"
                if captcha_endpoint.startswith("/")
                else f"https://sp.srmist.edu.in/{captcha_endpoint}"
            )
            domain_proof = base64.b64encode(
                f"{sc['nonce']}:sp.srmist.edu.in".encode()
            ).decode()

            img_res = s.get(
                captcha_url,
                headers={
                    "Referer": login_url,
                    "X-Domain-Proof": domain_proof,
                    "Accept": "image/png, image/jpeg, image/svg+xml, image/*",
                },
                timeout=10,
            )
            captcha_data_uri = f"data:image/png;base64,{base64.b64encode(img_res.content).decode('utf-8')}"

        hi.update({"sec_config": sc, "init_time": get_sgt_now().timestamp()})
        return jsonify(
            {
                "ok": True,
                "session_token": save_session(s, hi),
                "captcha_image": captcha_data_uri,
            }
        )
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/login/complete", methods=["POST"])
def complete_login():
    d = request.json or {}
    un = d.get("username", "").split("@")[0].strip()
    sp_pw = d.get("sp_password", "")
    acad_pw = d.get("acad_password", "")
    cap = d.get("captcha", "").strip()
    tk = d.get("session_token", "")

    if not all([un, sp_pw, acad_pw, cap, tk]):
        return jsonify({"ok": False, "error": "Missing fields"}), 400

    try:
        hi = dict(serializer.loads(tk).get("extra", {}))
        sc, it = (
            hi.pop("sec_config", {}),
            hi.pop("init_time", get_sgt_now().timestamp() - 15),
        )
    except Exception:
        return jsonify({"ok": False, "error": "Expired token"}), 401

    s = make_session(tk)
    s.headers.update(
        {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://sp.srmist.edu.in",
            "Referer": f"{STUDENT_PORTAL_URL}/students/loginManager/youLogin.jsp",
        }
    )

    p = {
        "username": un,
        "password": sp_pw,
        "captcha": cap,
        "fpPayload": "",
        "fpToken": "",
    }
    p.update({k: v for k, v in hi.items() if k.startswith("ph_")})

    now_ms = int(get_sgt_now().timestamp() * 1000)
    top_ms = int((get_sgt_now().timestamp() - it) * 1000)
    tm = generate_telemetry(
        len(un),
        len(sp_pw),
        now_ms,
        top_ms if top_ms > 5000 else random.randint(7500, 15000),
    )
    p["telemetryPayload"] = base64.b64encode(
        json.dumps(tm, separators=(",", ":")).encode()
    ).decode()

    if df := sc.get("domainFieldName"):
        p[df] = base64.b64encode(b"ni.ude.tsimrs.ps").decode()
    if cf := sc.get("captchaFieldName"):
        cx, cy = random.randint(40, 150), random.randint(15, 60)
        p[cf] = base64.b64encode(
            f"{cx}{sc.get('randomDelimiter', '-')}{cy}".encode()
        ).decode()

    try:
        res = s.post(
            f"{STUDENT_PORTAL_URL}/LoginServlet",
            data=p,
            allow_redirects=False,
            timeout=20,
        )
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 502

    if (
        res.status_code == 302
        or "Student Profile" in res.text
        or "HRDSystem" in res.text
    ):
        try:
            s = authenticate_academia_portal(s, f"{un}@srmist.edu.in", acad_pw)
        except Exception as ze:
            print("Background Academia login failed:", ze)
        return jsonify({"ok": True, "session_token": save_session(s)})

    elif "invalid captcha" in res.text.lower():
        return jsonify({"ok": False, "error": "Invalid Captcha."}), 401
    elif (
        "invalid credentials" in res.text.lower()
        or "invalid userid" in res.text.lower()
    ):
        return jsonify(
            {"ok": False, "error": "Invalid Student Portal Credentials."}
        ), 401

    return jsonify({"ok": False, "error": "Server rejected payload."}), 401


# ==========================================
# DATA SCRAPERS
# ==========================================
def fetch_academia_zoho_html(s, url):
    res = s.get(url, headers={"X-Requested-With": "XMLHttpRequest"})
    txt = res.text
    m = re.search(r"pageSanitizer\.sanitize\('(.+?)'\)", txt, re.DOTALL) or re.search(
        r'zmlvalue="(.+?)"', txt, re.DOTALL
    )
    if not m:
        return None
    raw = (
        m.group(1)
        .replace(r"\x22", '"')
        .replace(r"\x27", "'")
        .replace(r"\/", "/")
        .replace(r"\-", "-")
        .replace(r"\n", "\n")
        .replace(r"\t", "\t")
    )
    return BeautifulSoup(html.unescape(raw), "html.parser")


def scrape_academia_timetable_and_calendar(s):
    batch, my_slots, grid, active_indices = "2", {}, {}, []
    today_do, calendar_map = None, {}

    soup_tt = fetch_academia_zoho_html(
        s, f"{ACADEMIA_PORTAL_URL}page/My_Time_Table_2023_24"
    )
    if soup_tt:
        lbl = soup_tt.find("td", string=re.compile(r"Batch:", re.I))
        batch = "1" if lbl and "1" in lbl.find_next_sibling("td").get_text() else "2"
        for t in soup_tt.find_all("table"):
            tds = t.find_all(["td", "th"])
            if any("slot" in td.get_text().lower() for td in tds):
                headers = [
                    td.get_text(strip=True).lower()
                    for td in t.find("tr").find_all(["td", "th"])
                ]
                if "slot" not in headers:
                    continue
                nc, sc, tc = len(headers), headers.index("slot"), 2
                rc = 9 if len(headers) > 9 else len(headers) - 1
                for i in range(nc, len(tds), nc):
                    chunk = tds[i : i + nc]
                    if len(chunk) >= nc and chunk[tc].get_text(strip=True):
                        for s_str in (
                            chunk[sc].get_text(strip=True).strip("-").split("-")
                        ):
                            s_str = s_str.strip()
                            if s_str:
                                my_slots[s_str] = {
                                    "Title": chunk[tc].get_text(strip=True),
                                    "Room": chunk[rc].get_text(strip=True)
                                    if rc < len(chunk)
                                    else "",
                                }
                break

        suffix = "Batch_1" if batch == "1" else "batch_2"
        soup_uni = fetch_academia_zoho_html(
            s, f"{ACADEMIA_PORTAL_URL}page/Unified_Time_Table_2025_{suffix}"
        )
        rows = soup_uni.find_all("tr") if soup_uni else []
        times = (
            [
                td.get_text(strip=True).replace("\t", "")
                for td in rows[0].find_all("td")[1:]
            ]
            if rows
            else []
        )
        matrix = {}
        for r in rows:
            if "Day" in r.get_text():
                cells = r.find_all("td")
                if cells:
                    matrix[cells[0].get_text(strip=True)] = [
                        td.get_text(strip=True) for td in cells[1:]
                    ]

        has_class = [False] * len(times)
        for day, slots in matrix.items():
            grid[day] = []
            for i, slot_str in enumerate(slots[: len(times)]):
                parts = slot_str.split("/")
                match = next(
                    (my_slots[p.strip()] for p in parts if p.strip() in my_slots), None
                )
                if match:
                    has_class[i] = True
                grid[day].append(
                    {
                        "time": times[i] if i < len(times) else "",
                        "title": match["Title"] if match else None,
                        "room": match["Room"] if match else "",
                        "isLab": slot_str.strip().upper().startswith("P")
                        and match is not None,
                        "slots": slot_str,
                    }
                )
        active_indices = [i for i, v in enumerate(has_class) if v]

    soup_cal = fetch_academia_zoho_html(
        s, f"{ACADEMIA_PORTAL_URL}page/Academic_Planner_2026_27_ODD"
    )
    if soup_cal and soup_cal.find("table"):
        now = get_sgt_now()
        month_range, month_nums = range(0, 6), [7, 8, 9, 10, 11, 12]
        rows = soup_cal.find("table").find_all("tr")
        for block_idx in month_range:
            dt_idx, do_idx, month_num = (
                block_idx * 5,
                block_idx * 5 + 3,
                month_nums[block_idx],
            )
            for row in rows:
                cells = row.find_all("td")
                if len(cells) > do_idx:
                    date_val, do_val = (
                        cells[dt_idx].get_text(strip=True),
                        cells[do_idx].get_text(strip=True),
                    )
                    if date_val and do_val and do_val.isdigit():
                        try:
                            day = int(date_val)
                            if 1 <= day <= 31:
                                date_key = f"{now.year}-{month_num:02d}-{day:02d}"
                                calendar_map[date_key] = f"Day {do_val}"
                                if day == now.day and month_num == now.month:
                                    today_do = f"Day {do_val}"
                        except:
                            pass

    return {
        "DayOrder": today_do,
        "Calendar": calendar_map,
        "ActiveCols": active_indices,
        "Schedule": grid,
        "Batch": batch,
    }


def scrape_student_portal_attendance(s):
    res = s.post(
        f"{STUDENT_PORTAL_URL}/students/report/studentAttendanceDetails.jsp",
        data={"iden": "1", "filter": "", "hdnFormDetails": "1"},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    if res.status_code != 200:
        return []
    data = []
    for table in BeautifulSoup(res.text, "html.parser").find_all(
        "table", class_="table"
    ):
        headers = [th.get_text(strip=True).lower() for th in table.find_all("th")]
        if "code" in headers and "max. hours" in headers:
            tbody = table.find("tbody")
            if not tbody:
                continue
            for tr in tbody.find_all("tr"):
                cols = tr.find_all("td")
                if len(cols) >= 6:
                    code = cols[0].get_text(strip=True)
                    data.append(
                        {
                            "Code": code,
                            "Title": cols[1].get_text(strip=True),
                            "Conducted": cols[2].get_text(strip=True),
                            "Attended": cols[3].get_text(strip=True),
                            "Absent": cols[4].get_text(strip=True),
                            "Percentage": cols[5].get_text(strip=True),
                            "Category": "Practical"
                            if code.endswith(("P", "L", "J"))
                            else "Theory",
                        }
                    )
            break
    return data


def scrape_student_portal_marks(s):
    res = s.post(
        f"{STUDENT_PORTAL_URL}/students/report/studentInternalMarkDetails.jsp",
        data={"iden": "13", "filter": "", "hdnFormDetails": "1"},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    if res.status_code != 200:
        return []
    data = []
    for table in BeautifulSoup(res.text, "html.parser").find_all(
        "table", class_="table"
    ):
        tbody = table.find("tbody")
        if not tbody:
            continue
        for tr in tbody.find_all("tr"):
            cols = tr.find_all("td")
            if len(cols) >= 3 and "No Record found" not in tr.get_text():
                mark_max = cols[2].get_text(strip=True)
                scored, max_mark = 0, 0
                if "/" in mark_max:
                    parts = mark_max.split("/")
                    scored, max_mark = parts[0].strip(), parts[1].strip()
                data.append(
                    {
                        "Code": cols[0].get_text(strip=True),
                        "Title": cols[1].get_text(strip=True),
                        "Components": [
                            {"name": "Total", "scored": scored, "max": max_mark}
                        ],
                    }
                )
    return data


# ==========================================
# APPLICATION API ENDPOINTS
# ==========================================
@app.route("/api/profile", methods=["GET"])
def get_profile():
    if not (tk := request.headers.get("X-Session-Token")):
        return jsonify({"ok": False, "error": "No token"}), 401
    s = make_session(tk)
    s.headers.update(
        {
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"{STUDENT_PORTAL_URL}/students/template/HRDSystem.jsp",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        }
    )

    try:
        res = s.post(
            f"{STUDENT_PORTAL_URL}/students/report/studentProfile.jsp",
            data={
                "iden": "1",
                "filter": "",
                "hdnFormDetails": "1",
                "csrfPreventionSalt": "",
            },
            timeout=20,
        )
        if "youLogin.jsp" in res.text or res.status_code != 200:
            return jsonify({"ok": False, "error": "SESSION_EXPIRED"}), 401

        soup = BeautifulSoup(res.text, "html.parser")
        td = lambda l: (
            (
                div.get_text(strip=True)
                if (div := sib.find("div"))
                else sib.get_text(strip=True)
            )
            if (t := soup.find(lambda x: x.name == "td" and l in x.get_text()))
            and (sib := t.find_next_sibling("td"))
            else ""
        )

        return jsonify(
            {
                "ok": True,
                "name": td("Student Name") or "Unknown",
                "reg": td("Register No.") or td("Register No") or "Unknown",
                "program": td("Program") or td("Department") or "",
                "sem": td("Semester") or "",
                "email": td("Email ID") or td("E-Mail") or "",
            }
        )
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/data", methods=["GET"])
def get_data():
    if not (tk := request.headers.get("X-Session-Token")):
        return jsonify({"ok": False, "error": "No token"}), 401

    s = make_session(tk)
    is_sync = request.args.get("sync") == "true"

    try:
        s.headers.update(
            {"Referer": f"{STUDENT_PORTAL_URL}/students/template/HRDSystem.jsp"}
        )

        if is_sync:
            return jsonify(
                {
                    "ok": True,
                    "Attendance": scrape_student_portal_attendance(s),
                    "Marks": scrape_student_portal_marks(s),
                }
            )
        else:
            return jsonify(
                {
                    "ok": True,
                    **scrape_academia_timetable_and_calendar(s),
                    "Attendance": scrape_student_portal_attendance(s),
                    "Marks": scrape_student_portal_marks(s),
                }
            )
    except Exception as e:
        import traceback

        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/health", methods=["GET", "HEAD"])
def health_check():
    return "", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
