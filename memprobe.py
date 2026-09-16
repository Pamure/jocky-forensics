import sys, json
sys.path.insert(0, '.')
from jocky.rt import winapi
rows = winapi.list_processes()
seen, denied = [], 0
for r in rows:
    h = winapi._open_process(r["pid"])
    if h:
        seen.append(r["pid"])
        winapi._close(h)
    else:
        denied += 1
print(json.dumps({"opened": len(seen), "denied": denied, "total": len(rows)}))
