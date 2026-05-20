import subprocess
import json

from config import CAPA_PATH

class CapaRunner:

    def analyze(self, filepath):

        command = [
            CAPA_PATH,
            filepath,
            "-j"
        ]

        try:

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )

            data = json.loads(result.stdout)

            capabilities = []

            rules = data.get("rules", {})

            for rule_name, rule_data in rules.items():

                meta = rule_data.get("meta", {})

                capabilities.append({
                    "name": rule_name,
                    "namespace": meta.get("namespace", "unknown"),
                    "attck": meta.get("att&ck", [])
                })

            return capabilities

        except Exception as e:

            return [{
                "error": str(e)
            }]