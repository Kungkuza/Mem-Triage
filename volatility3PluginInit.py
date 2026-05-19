import subprocess
import json
from config import VOLATILITY_PATH, MEMORY_IMAGE

def run_volatility(plugin):
    command = [
        "python",
        VOLATILITY_PATH,
        "-f",
        MEMORY_IMAGE,
        "-r",
        "json",
        plugin
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )

        return json.loads(result.stdout)

    except subprocess.CalledProcessError as e:
        print(f"[!] Volatility error: {plugin}")
        print(e.stderr)
        return None