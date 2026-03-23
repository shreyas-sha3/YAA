import re
from bs4 import BeautifulSoup
import datetime

html_doc = """
<table align='center' cellspacing='0' cellpadding='0' border='1' style='border-color:#b4bed1'><th bgcolor='#410b5b' style='height:30px;padding:2px;'><strong><Font size=2 color = '#ffffff'>Dt</strong></font><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>Day</font></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>Jan '26</font></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>DO</font></strong></th><th bgcolor='#410b5b'><strong></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>Dt</font></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>Day</font></strong></th><th bgcolor='#410b5b' ><strong><Font size=2 color = '#ffffff'>Feb '26</font></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>DO</font></strong></th><th bgcolor='#410b5b'><strong></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>Dt</font></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>Day</font></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>Mar '26</font></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>DO</font></strong></th><th bgcolor='#410b5b'><strong></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>Dt</font></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>Day</font></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>Apr '26</font></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>DO</font></strong></th><th bgcolor='#410b5b'><strong></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>Dt</font></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>Day</font></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>May '26</font></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>DO</font></strong></th><th bgcolor='#410b5b'><strong></strong><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>Dt</strong></font><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>Day</font></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>Jun '26</font></strong></th><th bgcolor='#410b5b'><strong><Font size=2 color = '#ffffff'>DO</font></strong></th><th bgcolor='#410b5b'><strong></strong></th><tr><td bgcolor='#9a59b3' style='padding:5px'><Font size=2 color = '#FFFFFF'><strong>1</strong></td><td bgcolor='#354a5f' style='padding:5px'><Font size=2 color = '#FFFFFF'>Thu</td><td align = 'center'  bgcolor='#ccade1' style='padding:5px'><Font size=2 color = '#000000' style='font-weight:bold;'><strong>New Year’s Day - Holiday</strong></Font></td><td align = 'center' bgcolor='#587a4c' style='padding:5px'><Font size=2 color = '#ffffff'> - </font></td><td bgcolor='#4c7b8e'><Font size=2 color = '#ffffff'> - </font></td><td bgcolor='#9a59b3' style='padding:5px'><Font size=2 color = '#FFFFFF'><strong>1</strong></td><td bgcolor='#354a5f' style='padding:5px'><Font size=2 color = '#FFFFFF'>Sun</td><td align = 'center'  bgcolor='#ccade1' style='padding:5px'><Font size=2 color = '#000000' style='font-weight:bold;'><strong>Thaipoosam - Holiday</strong></Font></td><td align = 'center' bgcolor='#587a4c' style='padding:5px'><Font size=2 color = '#ffffff'> - </font></td><td bgcolor='#4c7b8e'><Font size=2 color = '#ffffff'> - </font></td><td bgcolor='#9a59b3' style='padding:5px'><Font size=2 color = '#FFFFFF'><strong>1</strong></td><td bgcolor='#354a5f' style='padding:5px'><Font size=2 color = '#FFFFFF'>Sun</td><td align = 'center'  bgcolor='#ccade1' style='padding:5px'><Font size=2 color = '#000000' style='font-weight:bold;'><strong></strong></Font></td><td align = 'center' bgcolor='#587a4c' style='padding:5px'><Font size=2 color = '#ffffff'> - </font></td><td bgcolor='#4c7b8e'><Font size=2 color = '#ffffff'> - </font></td><td bgcolor='#9a59b3' style='padding:5px'><Font size=2 color = '#FFFFFF'><strong>1</strong></td><td bgcolor='#354a5f' style='padding:5px'><Font size=2 color = '#FFFFFF'>Wed</td><td align = 'center'  bgcolor='#ccade1' style='padding:5px'><Font size=2 color = '#000000' style='font-weight:bold;'><strong></strong></Font></td><td align = 'center' bgcolor='#e6e2d3' style='padding:5px'>4</td><td bgcolor='#4c7b8e'><Font size=2 color = '#ffffff'> - </font></td><td bgcolor='#9a59b3' style='padding:5px'><Font size=2 color = '#FFFFFF'><strong>1</strong></td><td bgcolor='#354a5f' style='padding:5px'><Font size=2 color = '#FFFFFF'>Fri</td><td align = 'center'  bgcolor='#ccade1' style='padding:5px'><Font size=2 color = '#000000' style='font-weight:bold;'><strong>May Day - Holiday</strong></Font></td><td align = 'center' bgcolor='#587a4c' style='padding:5px'><Font size=2 color = '#ffffff'> - </font></td><td bgcolor='#4c7b8e'><Font size=2 color = '#ffffff'> - </font></td><td bgcolor='#9a59b3' style='padding:5px'><Font size=2 color = '#FFFFFF'><strong>1</strong></td><td bgcolor='#354a5f' style='padding:5px'><Font size=2 color = '#FFFFFF'>Mon</td><td align = 'center'  bgcolor='#ccade1' style='padding:5px'><Font size=2 color = '#000000' style='font-weight:bold;'><strong></strong></Font></td><td align = 'center' bgcolor='#587a4c' style='padding:5px'><Font size=2 color = '#ffffff'> - </font></td><td bgcolor='#4c7b8e'><Font size=2 color = '#ffffff'> - </font></td></tr>
</table>
"""

soup = BeautifulSoup(html_doc, "html.parser")
rows = soup.find("table").find_all("tr")[1:]
month_range = range(0, 6)
month_nums = [1, 2, 3, 4, 5, 6]
year_base = 2026

calendar_map = {}
for block_idx in month_range:
    dt_idx = block_idx * 5
    do_idx = block_idx * 5 + 3
    month_num = month_nums[block_idx]

    for row in rows:
        cells = row.find_all("td")
        if len(cells) > do_idx:
            date_val = cells[dt_idx].get_text(strip=True)
            do_val = cells[do_idx].get_text(strip=True)
            
            print(f"month={month_num} date={date_val} do_val='{do_val}'")
            if date_val and do_val and do_val.isdigit():
                day = int(date_val)
                date_key = f"{year_base}-{month_num:02d}-{day:02d}"
                calendar_map[date_key] = f"Day {do_val}"

print("calendar_map contains:")
for k, v in calendar_map.items():
    print(k, v)
