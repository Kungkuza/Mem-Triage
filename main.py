from volatility_runner import run_volatility
from ioc_parser import (
    extract_suspicious_processes,
    extract_injected_regions
)

from pe_analyzer import PEAnalyzer
from capa_runner import CapaRunner

from config import VOL_PLUGINS

from colorama import init, Fore
from tabulate import tabulate

import os

init()

def print_banner():

    print(Fore.CYAN + r"""
 __  __                      _______     _             
|  \/  | ___ _ __ ___       |__   __| __(_) __ _  __ _ 
| |\/| |/ _ \ '_ ` _ \ _______| | | '__| |/ _` |/ _` |
| |  | |  __/ | | | | |______| | | |  | | (_| | (_| |
|_|  |_|\___|_| |_| |_|      |_| |_|  |_|\__,_|\__, |
                                                |___/
""")


def main():

    print_banner()

    volatility_results = {}

    print(Fore.CYAN + "\n[+] Running Volatility Plugins\n")

    for plugin in VOL_PLUGINS:

        print(Fore.YELLOW + f"[*] {plugin}")

        data = run_volatility(plugin)

        if data:
            volatility_results[plugin] = data

    suspicious_processes = extract_suspicious_processes(
        volatility_results.get("windows.pslist", [])
    )

    suspicious_regions = extract_injected_regions(
        volatility_results.get("windows.malfind", [])
    )

    print(Fore.RED + f"\n[!] Suspicious Processes: {len(suspicious_processes)}")
    print(Fore.RED + f"[!] Suspicious Memory Regions: {len(suspicious_regions)}")

    pe_analyzer = PEAnalyzer()
    capa_runner = CapaRunner()

    dumped_files = []

    for root, dirs, files in os.walk("dumps"):

        for file in files:

            if file.endswith((".exe", ".dll")):

                dumped_files.append(
                    os.path.join(root, file)
                )

    results_table = []

    print(Fore.CYAN + "\n[+] Running PE + CAPA Analysis\n")

    for sample in dumped_files:

        print(Fore.YELLOW + f"[*] Analyzing: {sample}")

        pe_results = pe_analyzer.analyze(sample)

        capa_results = capa_runner.analyze(sample)

        entropy_hits = len(
            pe_results.get("entropy_flags", [])
        )

        suspicious_imports = ", ".join(
            pe_results.get("suspicious_imports", [])
        )

        capabilities = []

        for cap in capa_results:

            if "name" in cap:
                capabilities.append(cap["name"])

        top_caps = capabilities[:5]

        results_table.append([
            os.path.basename(sample),
            entropy_hits,
            suspicious_imports,
            "\n".join(top_caps)
        ])

    print(Fore.CYAN + "\n[+] Analysis Report\n")

    print(tabulate(
        results_table,
        headers=[
            "File",
            "Entropy Flags",
            "Suspicious Imports",
            "Top CAPA Capabilities"
        ],
        tablefmt="grid"
    ))


if __name__ == "__main__":
    main()