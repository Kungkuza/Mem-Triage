from volatility3PluginInit import run_volatility
from iocIdenitifer import (
    extract_suspicious_processes,
    extract_malfind_regions
)
from yaraScanner import YaraScanner
from pefileAnalyzer import PEAnalyzer

from config import VOL_PLUGINS, YARA_RULES

from tabulate import tabulate
from colorama import Fore, init

init()

def main():

    print(Fore.CYAN + "\n[+] Running Volatility Plugins\n")

    results = {}

    for plugin in VOL_PLUGINS:
        print(Fore.YELLOW + f"[*] Executing: {plugin}")

        data = run_volatility(plugin)

        if data:
            results[plugin] = data

    print(Fore.CYAN + "\n[+] Parsing IOCs\n")

    suspicious_procs = extract_suspicious_processes(
        results.get("windows.pslist", [])
    )

    suspicious_regions = extract_malfind_regions(
        results.get("windows.malfind", [])
    )

    print(Fore.RED + f"[!] Suspicious Processes: {len(suspicious_procs)}")
    print(Fore.RED + f"[!] Suspicious Memory Regions: {len(suspicious_regions)}")

    yara_scanner = YaraScanner(YARA_RULES)
    pe_analyzer = PEAnalyzer()

    print(Fore.CYAN + "\n[+] Analyzing Dumped Files\n")

    dumped_files = [
        "dumps/sample1.exe",
        "dumps/sample2.dll"
    ]

    final_results = []

    for file in dumped_files:

        yara_hits = yara_scanner.scan_file(file)

        pe_results = pe_analyzer.analyze(file)

        final_results.append({
            "file": file,
            "yara_hits": yara_hits,
            "suspicious_pe": pe_results.get("suspicious", [])
        })

    print(Fore.CYAN + "\n[+] Final Report\n")

    table = []

    for result in final_results:

        table.append([
            result["file"],
            ", ".join(result["yara_hits"]),
            ", ".join(result["suspicious_pe"])
        ])

    print(tabulate(
        table,
        headers=["File", "YARA Hits", "PE Indicators"],
        tablefmt="grid"
    ))


if __name__ == "__main__":
    main()