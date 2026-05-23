from volatility3PluginInit import run_volatility
from iocIdenitifer import (
    extract_suspicious_processes,
    extract_malfind_regions
)

from pefileAnalyzer import PEAnalyzer
from capaRunner import CapaRunner

from config import DUMP_PLUGINS, VOL_PLUGINS, DUMP_DIR

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

    print(Fore.CYAN + "\n[+] Running Volatility Plugins\n")

    for plugin in VOL_PLUGINS:
        print(Fore.YELLOW + f"[*] {plugin}")
        #Makes Volatility to use "-r json" 
        data = run_volatility(plugin, dump_mode=False) 
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
    print(Fore.CYAN + "\n[+] Extracting Malicious Binary Payloads to Disk...\n")
    for dump_plugin in DUMP_PLUGINS:
        print(Fore.YELLOW + f"[*] Carving active code layers via: {dump_plugin}")
        
        run_volatility(dump_plugin, dump_mode=True)
    
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

    pe_analyzer = PEAnalyzer()
    capa_runner = CapaRunner()

    print(Fore.RED + f"\n[!] Suspicious Processes: {len(suspicious_processes)}")
    print(Fore.RED + f"[!] Suspicious Memory Regions: {len(suspicious_regions)}")

    dumped_files = []

    for root, dirs, files in os.walk("dumps"):
        for file in files:
            if file.endswith((".exe", ".dll")):

                dumped_files.append(
                    os.path.join(root, file)
                )

    results_table = []

    print(Fore.CYAN + "\n[+] Running PE + CAPA Analysis on Carved Files...\n")

    for sample_path in dumped_files:
        
        file_name = os.path.basename(sample_path)
        print(Fore.YELLOW + f"[*] Analyzing File: {file_name}")

        #files passed to analyzers
        pe_results = pe_analyzer.analyze(sample_path)
        capa_results = capa_runner.analyze(sample_path)

        #pull the results from your tool returns
        entropy_hits = len(pe_results.get("entropy_flags", [])) if pe_results else 0
        suspicious_imports = ", ".join(pe_results.get("suspicious_imports", [])) if pe_results else "None"

        capabilities = []
        if capa_results:
            for cap in capa_results:
                if "name" in cap:
                    capabilities.append(cap["name"])

        top_caps = capabilities[:5]

        #Appends to the summary data grid
        results_table.append([
            file_name,
            entropy_hits,
            suspicious_imports,
            "\n".join(top_caps) if top_caps else "No major capabilities flagged."
        ])

    # Print out final summary report
    print(Fore.CYAN + "\n[+] Final Analysis Summary Report\n")
    print(Fore.WHITE + "=" * 90)
    for row in results_table:
        print(Fore.WHITE + f"Artifact Target : {row[0]}")
        print(Fore.WHITE + f"Entropy Flags   : {row[1]}")
        print(Fore.WHITE + f"Suspicious APIs : {row[2]}")
        print(Fore.GREEN + f"Capa Behaviors  :\n{row[3]}")
        print(Fore.WHITE + "=" * 90)
if __name__ == "__main__":
    main()