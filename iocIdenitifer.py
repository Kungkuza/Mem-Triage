SUSPICIOUS_PROCESS_NAMES = [
    "svch0st.exe",
    "expl0rer.exe",
    "temp.exe"
]

def extract_suspicious_processes(pslist_data):
    suspicious = []

    for proc in pslist_data:
        process_name = proc.get("ImageFileName", "").lower()

        if process_name in SUSPICIOUS_PROCESS_NAMES:
            suspicious.append(proc)

    return suspicious


def extract_malfind_regions(malfind_data):
    findings = []

    for entry in malfind_data:
        protection = entry.get("Protection", "")

        if "EXECUTE_READWRITE" in protection:
            findings.append(entry)

    return findings