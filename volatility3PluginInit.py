import os
import subprocess
import json
from config import VOLATILITY_PATH, MEMORY_IMAGE, DUMP_DIR

def run_volatility(plugin, dump_mode=False):
    command = [
        "python",
        VOLATILITY_PATH,
        "-f",
        MEMORY_IMAGE
    ]

    # Explicitly branch using the dump_mode parameter passed by main.py
    if dump_mode:
        if not os.path.exists(DUMP_DIR):
            os.makedirs(DUMP_DIR)
        command.extend(["-o", DUMP_DIR, plugin, "--dump"])
    else:
        command.extend(["-r", "json", plugin])

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",  #Fixes the charmap decode issue
            check=True
        )

        if dump_mode:
            return {"status": "dump_completed", "raw_logs": result.stdout}
        return json.loads(result.stdout)

    except subprocess.CalledProcessError as e:
        print(f"[!] Volatility error: {plugin}")
        print(e.stderr)
        return None
    except json.JSONDecodeError:
        print(f"[!] JSON parsing error on plugin output: {plugin}")
        return None