from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests, time, urllib.parse, re, html, datetime
from bs4 import BeautifulSoup

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class LoginRequest(BaseModel):
    email: str
    password: str

class AcademiaClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9", "Connection": "keep-alive"
        })
        self.base = "https://academia.srmist.edu.in"
        self.portal_url = f"{self.base}/portal/academia-academic-services/"

    # Removed pickle logic to prevent users from sharing sessions on the cloud
    def load_session(self): return False
    def save_session(self): pass

    def login(self, email, password):
        self.session.get(f"{self.base}/accounts/p/10002227248/signin?orgtype=40&serviceurl={urllib.parse.quote(self.portal_url + 'redirectFromLogin')}")
        csrf = self.session.cookies.get('iamcsrcoo') or self.session.cookies.get('_zcsr_tmp')
        if not csrf: return False
        self.session.headers.update({"x-zcsrf-token": f"iamcsrcoo={csrf}", "Referer": f"{self.base}/"})

        res = self.session.post(f"{self.base}/accounts/p/40-10002227248/signin/v2/lookup/{urllib.parse.quote(email)}",
                                data={"mode": "primary", "cli_time": str(int(time.time()*1000)), "orgtype": "40"}).json()
        zuid, digest = res.get('lookup', {}).get('identifier'), res.get('lookup', {}).get('digest')
        if not zuid: return False

        auth_res = self.session.post(f"{self.base}/accounts/p/40-10002227248/signin/v2/primary/{zuid}/password",
                                     params={"digest": digest, "cli_time": str(int(time.time()*1000)), "orgtype": "40"},
                                     data=f'{{"passwordauth":{{"password":"{password}"}}}}').json()

        next_url = auth_res.get('passwordauth', {}).get('redirect_uri') or auth_res.get('href')
        if auth_res.get('code') == 'SI303' and next_url and 'block-sessions' in next_url:
            self.session.delete(f"{self.base}/accounts/p/40-10002227248/webclient/v1/announcement/pre/blocksessions")
            next_url = self.session.post(f"{self.base}/accounts/p/40-10002227248/signin/v2/primary/{zuid}/password",
                                         params={"digest": digest, "cli_time": str(int(time.time()*1000)), "orgtype": "40"},
                                         data=f'{{"passwordauth":{{"password":"{password}"}}}}').json().get('passwordauth', {}).get('redirect_uri')

        if not next_url: return False
        if next_url.startswith('/'): next_url = self.base + next_url
        return "signinFrame" not in self.session.get(next_url).text

    def get_html(self, url):
        self.session.headers.update({"X-Requested-With": "XMLHttpRequest"})
        txt = self.session.get(url).text
        m = re.search(r"pageSanitizer\.sanitize\('(.+?)'\)", txt, re.DOTALL) or re.search(r'zmlvalue="(.+?)"', txt, re.DOTALL)
        return BeautifulSoup(html.unescape(m.group(1)).encode('utf-8').decode('unicode_escape'), 'html.parser') if m else None

    def get_student_info(self):
        try:
            rec = self.session.get(f"{self.portal_url}report/Student_Profile_Report?urlParams=%7B%7D").json().get("MODEL", {}).get("DATAJSONARRAY", [{}])[0].get("Name", "")
            return {"Name": rec.split(" - ")[1], "RegNo": rec.split(" - ")[0]} if " - " in rec else {"Name": rec}
        except: return None

    def get_academic_planner(self):
        dash = self.session.get(self.portal_url).text
        planner_link = (re.search(r'"PAGELINKNAME":"(Academic_Planner_[^"]+)"', dash) or [None, "Academic_Planner_2025_26_EVEN"])[1]
        soup = self.get_html(f"{self.portal_url}page/{planner_link}")
        if not soup or not soup.find('table'): return None

        now = datetime.datetime.now()
        is_even = "EVEN" in planner_link.upper()
        if is_even and 1 <= now.month <= 6:        block_idx = now.month - 1
        elif not is_even and 7 <= now.month <= 12: block_idx = now.month - 7
        else: return None

        dt_idx, do_idx = block_idx * 5, block_idx * 5 + 3
        for row in soup.find('table').find_all('tr')[1:]:
            cells = row.find_all('td')
            if len(cells) > do_idx and cells[dt_idx].get_text(strip=True) == str(now.day):
                do_val = cells[do_idx].get_text(strip=True)
                return f"Day {do_val}" if do_val.isdigit() else None
        return None

    def get_data(self):
        soup_tt = self.get_html(f"{self.portal_url}page/My_Time_Table_2025_26_EVEN") or self.get_html(f"{self.portal_url}page/My_Time_Table_2023_24")
        batch, my_slots = "2", {}
        if soup_tt:
            lbl = soup_tt.find('td', string=re.compile(r'Batch:', re.I))
            batch = "1" if lbl and '1' in lbl.find_next_sibling('td').get_text() else "2"
            for t in soup_tt.find_all('table'):
                tds = t.find_all(['td', 'th'])
                if any('slot' in td.get_text().lower() for td in tds):
                    headers = [td.get_text(strip=True).lower() for td in t.find('tr').find_all(['td', 'th'])]
                    nc, sc, tc, rc = len(headers), headers.index('slot'), 2, 9
                    for i in range(nc, len(tds), nc):
                        chunk = tds[i:i+nc]
                        if len(chunk) >= nc and chunk[tc].get_text(strip=True):
                            for s in chunk[sc].get_text(strip=True).strip('-').split('-'):
                                if s.strip(): my_slots[s.strip()] = {"Title": chunk[tc].get_text(strip=True), "Room": chunk[rc].get_text(strip=True)}
                    break

        soup_uni = self.get_html(f"{self.portal_url}page/Unified_Time_Table_2025_{'Batch_1' if batch=='1' else 'batch_2'}")
        rows = soup_uni.find_all('tr') if soup_uni else []
        times = [td.get_text(strip=True).replace('\t', '') for td in rows[0].find_all('td')[1:]] if rows else []
        matrix = {r.find_all('td')[0].get_text(strip=True): [td.get_text(strip=True) for td in r.find_all('td')[1:]] for r in rows if "Day" in r.get_text()}

        has_class = [False] * len(times)
        grid = {}
        for day, slots in matrix.items():
            grid[day] = []
            for i, slot_str in enumerate(slots[:len(times)]):
                match = next((my_slots[s.strip()] for s in slot_str.split('/') if s.strip() in my_slots), None)
                if match: has_class[i] = True
                grid[day].append({"time": times[i], "title": match["Title"] if match else None, "room": match["Room"] if match else ""})
        active_indices = [i for i, v in enumerate(has_class) if v]

        soup_att = self.get_html(f"{self.portal_url}page/My_Attendance")
        att, mks, seen_att, seen_mks = [], [], set(), set()
        if soup_att:
            for t in soup_att.find_all('table'):
                trows = t.find_all('tr')
                if not trows: continue
                hdr = trows[0].get_text()
                for r in trows[1:]:
                    c = r.find_all('td', recursive=False)
                    if "Attn %" in hdr and len(c) >= 9:
                        code = c[0].get_text(" ", strip=True)
                        if code not in seen_att:
                            seen_att.add(code)
                            att.append({"Title": c[1].get_text(strip=True), "Attn": c[8].get_text(strip=True)})
                    elif "Test Performance" in hdr and len(c) >= 3:
                        code = c[0].get_text(strip=True)
                        if code not in seen_mks:
                            seen_mks.add(code)
                            parts = []
                            for td in c[2].find_all('td'):
                                raw = td.get_text(": ", strip=True)
                                m2 = re.match(r'(.+?)/(\d+\.?\d*):\s*(\d+\.?\d*)', raw)
                                if m2: parts.append(f"{m2.group(1)}: {m2.group(3)}/{m2.group(2)}")
                                elif raw: parts.append(raw)
                            if parts:
                                title = c[1].get_text(strip=True) if len(c) > 1 else code
                                mks.append({"Title": title, "Marks": " | ".join(parts)})

        return {"DayOrder": self.get_academic_planner(), "Schedule": grid, "ActiveCols": active_indices,
                "Batch": batch, "Attendance": att, "Marks": mks}

@app.post("/api/timetable")
def fetch_timetable(req: LoginRequest):
    api = AcademiaClient()

    if not api.login(req.email, req.password):
        raise HTTPException(status_code=401, detail="Invalid credentials or SRM portal is down.")

    prof = api.get_student_info()
    data = api.get_data()

    if not prof:
        raise HTTPException(status_code=500, detail="Failed to fetch student profile.")

    return {
        "success": True,
        "profile": prof,
        "data": data
    }
