import yara

class YaraScanner:

    def __init__(self, rule_path):
        self.rules = yara.compile(filepath=rule_path)

    def scan_file(self, filepath):
        try:
            matches = self.rules.match(filepath)

            return [match.rule for match in matches]

        except Exception as e:
            print(f"[!] YARA scan failed: {filepath}")
            print(e)
            return []