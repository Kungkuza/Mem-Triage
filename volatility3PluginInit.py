import os
import subprocess
import json
from config import VOLATILITY_PATH

def run_volatility(plugin, image_path, dump_mode=False, dump_dir=None):
    command = [
        "python",
        VOLATILITY_PATH,
        "-f",
        image_path
    ]

    # Explicitly branch using the dump_mode parameter passed by main.py
    if dump_mode:
        if not os.path.exists(dump_dir):
            os.makedirs(dump_dir)
        command.extend(["-o", dump_dir, plugin, "--dump"])
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