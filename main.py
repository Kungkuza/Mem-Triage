from volatility3PluginInit import run_volatility
from iocIdenitifer import (
    extract_suspicious_processes,
    extract_malfind_regions
)

from pefileAnalyzer import PEAnalyzer
from capaRunner import CapaRunner

from config import DUMP_PLUGINS, VOL_PLUGINS

from colorama import init, Fore

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

    #Volatility3 raw cmdline output given before more specfic pointer ot suspcious processes and memory regions.
    print(Fore.MAGENTA + "\n[DUMPING RAW VOLATILITY DATA STRUCTURES]")
    for plugin_name, raw_data in volatility_results.items():
        print(Fore.MAGENTA + f"\n--- Raw Data Object for {plugin_name} ---")
        print(Fore.WHITE + str(raw_data)[:2000]) #Shortened
    print(Fore.MAGENTA + "-----------------------------------------\n")

    suspicious_processes = extract_suspicious_processes(
        volatility_results.get("windows.pslist", [])
    )

    suspicious_regions = extract_malfind_regions(
        volatility_results.get("windows.malfind", [])
    )

    print(Fore.RED + f"\n[!] Suspicious Processes Detected: {len(suspicious_processes)}")
    
    # Print out the names and PIDs of suspicious processes & some volatility output
    if suspicious_processes:
        print(Fore.YELLOW + "    --> Flagged Processes:")
        for proc in suspicious_processes:
    
            pid = proc.get("PID") or proc.get("UniqueProcessId", "N/A")
            name = proc.get("Name") or proc.get("ImageFileName", "Unknown")
            print(Fore.YELLOW + f"        [+] {name} (PID: {pid})")
    else:
        print(Fore.GREEN + "    --> No suspicious processes flagged.")
    
    print(Fore.RED + f"\n[!] Suspicious Memory Regions Detected: {len(suspicious_regions)}")
    
    if suspicious_regions:
        print(Fore.YELLOW + "    --> Flagged Malfind Regions:")
        for region in suspicious_regions:
            pid = region.get("PID") or region.get("ProcessId", "N/A")
            addr = region.get("Address") or region.get("BaseAddress", "0x0")
            hex_addr = hex(addr) if isinstance(addr, int) else str(addr)
            
            print(Fore.YELLOW + f"        [+] Injected chunk found in PID {pid} at memory address {hex_addr}")
    else:
        print(Fore.GREEN + "    --> No suspicious memory regions flagged.")

    #End of print
    #Start of extraction from raw data stream

    print(Fore.CYAN + "\n[+] Extracting malicious binaries from memory image...")
    from config import DUMP_PLUGINS, DUMP_DIR
    for dump_plugin in DUMP_PLUGINS:
        run_volatility(dump_plugin, dump_dir=DUMP_DIR)

    pe_analyzer = PEAnalyzer()
    capa_runner = CapaRunner()

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

    for process in suspicious_processes:
            pid = process.get("pid")
            process_name = process.get("name")
            raw_pe_bytes = process.get("raw_bytes")
            
            if not raw_pe_bytes or not raw_pe_bytes.startswith(b'MZ'):
                continue

            print(Fore.YELLOW + f"[*] Analyzing Streamed Process: {process_name} (PID: {pid})")

            pe_results = pe_analyzer.analyze(raw_pe_bytes)
            capa_results = capa_runner.analyze(raw_pe_bytes)

            entropy_hits = len(pe_results.get("entropy_flags", []))
            suspicious_imports = ", ".join(pe_results.get("suspicious_imports", []))

            capabilities = []
            for cap in capa_results:
                if "name" in cap:
                    capabilities.append(cap["name"])

            top_caps = capabilities[:5]

            results_table.append([
                f"{process_name}_{pid}.mem_stream",
                entropy_hits,
                suspicious_imports,
                "\n".join(top_caps)
            ])

    print(Fore.CYAN + "\n[+] Analysis Report\n")

if __name__ == "__main__":
    main()