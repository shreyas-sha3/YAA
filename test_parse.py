import requests
import time, urllib.parse, re, json, html
from bs4 import BeautifulSoup

# --- CREDENTIALS ---
EMAIL = "hk2768@srmist.edu.in"
PASSWORD = "H@ri@2006"

BASE = "https://academia.srmist.edu.in"
PORTAL = f"{BASE}/srm_university/academia-academic-services/"

def run_debugger():
    print(f"[*] Starting Login for {EMAIL}...")
    s = requests.Session()
    
    # Matching your exact browser headers
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0",
        "Accept": "*/*", 
        "Accept-Language": "en-US,en;q=0.5", 
        "Connection": "keep-alive"
    })

    # --- LOGIN SEQUENCE ---
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
    
    s.headers.update({
        "x-zcsrf-token": f"iamcsrcoo={csrf}",
        "Referer": f"{BASE}/",
        "Content-Type": "application/x-www-form-urlencoded"
    })

    lookup_url = f"{BASE}/accounts/p/40-10002227248/signin/v2/lookup/{urllib.parse.quote(EMAIL)}"
    res = s.post(lookup_url, data={"mode": "primary", "cli_time": str(int(time.time()*1000)), "orgtype": "40"}).json()
    zuid, digest = res.get('lookup', {}).get('identifier'), res.get('lookup', {}).get('digest')
    
    pw_payload = json.dumps({"passwordauth": {"password": PASSWORD}})
    auth_url = f"{BASE}/accounts/p/40-10002227248/signin/v2/primary/{zuid}/password"
    auth_res = s.post(auth_url, params={"digest": digest, "cli_time": str(int(time.time()*1000)), "orgtype": "40"}, data=pw_payload, headers={"Content-Type": "application/json"}).json()
    next_url = auth_res.get('passwordauth', {}).get('redirect_uri') or auth_res.get('href')

    if auth_res.get('code') == 'SI303' and next_url and 'block-sessions' in next_url:
        s.delete(f"{BASE}/accounts/p/40-10002227248/webclient/v1/announcement/pre/blocksessions")
        auth_res2 = s.post(auth_url, params={"digest": digest, "cli_time": str(int(time.time()*1000)), "orgtype": "40"}, data=pw_payload, headers={"Content-Type": "application/json"}).json()
        next_url = auth_res2.get('passwordauth', {}).get('redirect_uri')

    if next_url.startswith('/'): next_url = BASE + next_url
    s.get(next_url)
    print("[+] Login Successful!\n")

    # --- FETCHING DATA ---
    # Append the strict AJAX headers just like the browser
    s.headers.update({
        "X-Requested-With": "XMLHttpRequest",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin"
    })

    links_to_test = ["My_Time_Table_2023_24", "My_Attendance"]
    
    for link in links_to_test:
        print(f"=== Fetching: {link} ===")
        url = f"{PORTAL}page/{link}"
        
        resp = s.get(url)
        txt = resp.text
        
        print(f"[*] HTTP Status: {resp.status_code} | Length: {len(txt)}")
        
        if "pageSanitizer.sanitize" in txt:
            print("[*] SUCCESS: 'pageSanitizer.sanitize' wrapper found!")
            
            # Test the exact Regex we use in the backend
            m = re.search(r"pageSanitizer\.sanitize\('(.+?)'\)", txt, re.DOTALL)
            if m:
                print("[*] Regex matched! Extracting and parsing HTML...")
                raw = m.group(1)
                try:
                    raw = html.unescape(raw).encode('utf-8').decode('unicode_escape')
                except Exception:
                    raw = html.unescape(raw)
                
                soup = BeautifulSoup(raw, 'html.parser')
                tables = soup.find_all('table')
                print(f"[*] Parsed {len(tables)} tables. Preview of first text snippet:")
                print(f"    -> {soup.get_text(strip=True)[:100]}...\n")
            else:
                print("[!] ERROR: pageSanitizer found, but Regex failed to capture group.\n")
        else:
            print("[!] ERROR: 'pageSanitizer.sanitize' NOT found! Zoho gave us this instead:")
            print(f"{txt[:500]}\n")

if __name__ == "__main__":
    run_debugger()