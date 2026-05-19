import pefile

class PEAnalyzer:

    def analyze(self, filepath):

        results = {
            "imports": [],
            "sections": [],
            "suspicious": []
        }

        try:
            pe = pefile.PE(filepath)

            for section in pe.sections:
                sec_name = section.Name.decode(errors="ignore").strip("\x00")

                results["sections"].append({
                    "name": sec_name,
                    "entropy": section.get_entropy()
                })

                if section.get_entropy() > 7:
                    results["suspicious"].append(
                        f"High entropy section: {sec_name}"
                    )

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):

                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode()

                    results["imports"].append(dll_name)

                    suspicious_imports = [
                        "wininet.dll",
                        "ws2_32.dll",
                        "advapi32.dll"
                    ]

                    if dll_name.lower() in suspicious_imports:
                        results["suspicious"].append(
                            f"Suspicious import: {dll_name}"
                        )

            return results

        except Exception as e:
            return {
                "error": str(e)
            }