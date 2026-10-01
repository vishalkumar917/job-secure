"""Stand-in for the Volatility CLI used by runner tests (exercises the real subprocess path).

Behaviour is selected by the plugin argument:
  windows.pslist   -> prints a JSON row list
  windows.info     -> exits 1 with Volatility's symbol-requirement message
  windows.psscan   -> sleeps (timeout test)
  windows.malware.malfind -> "invalid choice" (alias fallback test); windows.malfind -> JSON
  windows.cmdline  -> prints environment-leak probe
"""

import json
import os
import sys
import time

args = sys.argv[1:]
plugin = next(a for a in args if a.startswith("windows."))
if plugin == "windows.pslist":
    print(json.dumps([{"PID": 4, "PPID": 0, "ImageFileName": "System", "__children": [
        {"PID": 300, "PPID": 4, "ImageFileName": "smss.exe", "__children": []}]}]))
elif plugin == "windows.info":
    sys.stderr.write("Unable to validate the plugin requirements: ['plugins.Info.kernel.symbol_table_name']\n")
    sys.exit(1)
elif plugin == "windows.psscan":
    time.sleep(30)
elif plugin == "windows.malware.malfind":
    sys.stderr.write(f"vol: error: argument PLUGIN: invalid choice {plugin} (choose from ...)\n")
    sys.exit(2)
elif plugin == "windows.malfind":
    print(json.dumps([{"PID": 1, "Process": "x", "Start VPN": 1, "End VPN": 2}]))
elif plugin == "windows.cmdline":
    leaked = [k for k in os.environ if "SECRET" in k.upper() or "API_KEY" in k.upper()]
    print(json.dumps([{"PID": 1, "Process": "probe", "Args": ",".join(leaked) or "clean"}]))
else:
    print("[]")
