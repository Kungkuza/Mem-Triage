import os
import subprocess
import json
from config import VOLATILITY_PATH, MEMORY_IMAGE, DUMP_DIR

def run_volatility(plugin dump__mode=False):
    command = [
        "python",
        VOLATILITY_PATH,
        "-f",
        MEMORY_IMAGE
    ]

    is_dumping_plugin = plugin in ["windows.malfind", "windows.pedump", "windows.dlllist"]

    if is_dumping_plugin:
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
            check=True
        )

        if is_dumping_plugin:
            return {"status": "dump_completed", "raw_logs": result.stdout}
        return json.loads(result.stdout)

    except subprocess.CalledProcessError as e:
        print(f"[!] Volatility error: {plugin}")
        print(e.stderr)
        return None
    except json.JSONDecodeError:
        print(f"[!] JSON parsing error on plugin output: {plugin}")
        return None