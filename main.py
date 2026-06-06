import os
import sys
import argparse
from volatility3PluginInit import run_volatility
from iocIdenitifer import (
    extract_suspicious_processes,
    extract_malfind_regions
)
from pefileAnalyzer import PEAnalyzer
from capaRunner import CapaRunner
from config import DUMP_PLUGINS, VOL_PLUGINS, get_unique_dump_dir
from colorama import init, Fore

SYSTEM_WHITELIST = ["lsass.exe", "MsMpEng.exe", "smartscreen.exe", "SearchUI.exe", "powershell.exe", "ftkimager.exe"]

init()

def print_banner():
    print(Fore.CYAN + r"""
 __  __          _ _____     _                 
|  \/  | ___ _ _(_) _   _ __(_)__ _ __ _  ___  
| |\/| |/ _ \ '_| | | | ' _| | _` / _` |/ _ \ 
| |  | |  __/ | | | | | |  | | (_| | (_| |  __/ 
|_|  |_|\___|_| |_| |_|_|  |_|\__,_|\__, |\___|
                                    |___/      
""")


def main():
    # 1. Argument Parsing & Dynamic Workspace Setup
    parser = argparse.ArgumentParser(description="Mem-Triage: Automated Memory Forensics Framework")
    parser.add_argument("-i", "--image", required=True, help="Path to the raw input memory image file")
    parser.add_argument("-p", "--pid", type=int, required=False, help="Specific PID to isolate and inspect on-screen")
    args = parser.parse_args()

    # Ensure memory image exists before launching overhead tasks
    if not os.path.exists(args.image):
        print(Fore.RED + f"[-] Error: Target memory image file not found at: {args.image}")
        sys.exit(1)

    print_banner()
    
    # Generate unique, isolated workspace folder for this execution run
    active_dump_dir = get_unique_dump_dir()
    print(f"[+] Local Workspace Initialized: {active_dump_dir}\n")

    volatility_results = {}
    print(Fore.CYAN + "[+] Running Volatility Plugins\n")

    # Pass the user-supplied memory target path explicitly down to Volatility
    for plugin in VOL_PLUGINS:
        print(Fore.YELLOW + f"[*] Running: {plugin}")
        data = run_volatility(plugin, image_path=args.image, dump_mode=False) 
        if data:
            volatility_results[plugin] = data

    # 2. Raw Memory Dump Telemetry Out
    print(Fore.MAGENTA + "\n[DUMPING RAW VOLATILITY DATA STRUCTURES]")
    for plugin_name, raw_data in volatility_results.items():
        print(Fore.MAGENTA + f"\n--- Raw Data Object for {plugin_name} ---")
        print(Fore.WHITE + str(raw_data)[:2000]) # Shortened output
    print(Fore.MAGENTA + "-----------------------------------------\n")

    # 3. Extraction & Whitelist Filtering (Resolving false positive noise)
    raw_suspicious_processes = extract_suspicious_processes(volatility_results.get("windows.pslist", []))
    raw_suspicious_regions = extract_malfind_regions(volatility_results.get("windows.malfind", []))

    # Apply structural optimization loops to clean up system baseline profiles
    suspicious_processes = []
    for proc in raw_suspicious_processes:
        pid = proc.get("PID") or proc.get("UniqueProcessId", "N/A")
        name = proc.get("Name") or proc.get("ImageFileName", "Unknown")
        is_hidden = proc.get("is_hidden", False)
        
        # User Targeted PID Check
        if args.pid and pid != args.pid:
            continue
        # Noise reduction heuristic filtration
        if name in SYSTEM_WHITELIST and not is_hidden:
            continue
        suspicious_processes.append(proc)

    suspicious_regions = []
    for region in raw_suspicious_regions:
        pid = region.get("PID") or region.get("ProcessId", "N/A")
        proc_name = region.get("ProcessName", "Unknown")
        is_hidden = region.get("is_hidden", False)
        
        # User Targeted PID Check
        if args.pid and pid != args.pid:
            continue
        # Noise reduction heuristic filtration
        if proc_name in SYSTEM_WHITELIST and not is_hidden:
            continue
        suspicious_regions.append(region)


    print(Fore.RED + f"\n[!] Suspicious Processes Detected (Filtered): {len(suspicious_processes)}")
    if suspicious_processes:
        print(Fore.YELLOW + "    --> Flagged Active Processes:")
        for proc in suspicious_processes:
            pid = proc.get("PID") or proc.get("UniqueProcessId", "N/A")
            name = proc.get("Name") or proc.get("ImageFileName", "Unknown")
            print(Fore.YELLOW + f"        [+] {name} (PID: {pid})")
    else:
        print(Fore.GREEN + "    --> No suspicious processes flagged.")

    print(Fore.RED + f"\n[!] Suspicious Memory Regions Detected (Filtered): {len(suspicious_regions)}")
    print(Fore.CYAN + "\n[+] Extracting Malicious Binary Payloads to Unique Directory...\n")
    
    # Direct Volatility to execute carving outputs into our clean dynamic folder directory
    for dump_plugin in DUMP_PLUGINS:
        print(Fore.YELLOW + f"[*] Carving active code layers via {dump_plugin} -> {active_dump_dir}")
        run_volatility(dump_plugin, image_path=args.image, dump_mode=True, dump_dir=active_dump_dir)
    
    if suspicious_regions:
        print(Fore.YELLOW + "    --> Flagged Malfind Regions:")
        for region in suspicious_regions:
            pid = region.get("PID") or region.get("ProcessId", "N/A")
            addr = region.get("Address") or region.get("BaseAddress", "0x0")
            hex_addr = hex(addr) if isinstance(addr, int) else str(addr)
            print(Fore.YELLOW + f"        [+] Injected chunk found in PID {pid} at memory address {hex_addr}")
    else:
        print(Fore.GREEN + "    --> No suspicious memory regions flagged.")

    # 5. Static Binary Triage Layer (PE file + Capa)

    pe_analyzer = PEAnalyzer()
    capa_runner = CapaRunner()

    print(Fore.RED + f"\n[!] Suspicious Processes Remaining in Queue: {len(suspicious_processes)}")
    print(Fore.RED + f"[!] Suspicious Memory Regions Remaining in Queue: {len(suspicious_regions)}")

    dumped_files = []
    for root, dirs, files in os.walk(active_dump_dir):
        for file in files:
            # FIX: Remove the strict .exe/.dll requirement. 
             # Volatility dumps malfind payloads as .dmp, .vac_dump, or extensionless hex files.
             file_path = os.path.join(root, file)
                
             # Ensure it's an actual file and not a subdirectory artifact
             if os.path.isfile(file_path):
                    dumped_files.append(file_path)

    results_table = []
    print(Fore.CYAN + f"\n[+] Running PE + CAPA Analysis on {len(dumped_files)} Carved Files...\n")

    for sample_path in dumped_files:
        file_name = os.path.basename(sample_path)
        print(Fore.YELLOW + f"[*] Analyzing File: {file_name}")

        pe_results = pe_analyzer.analyze(sample_path)
        capa_results = capa_runner.analyze(sample_path)

        entropy_hits = len(pe_results.get("entropy_flags", [])) if pe_results else 0
        suspicious_imports = ", ".join(pe_results.get("suspicious_imports", [])) if pe_results else "None"

        capabilities = []
        if capa_results:
            for cap in capa_results:
                if "name" in cap:
                    capabilities.append(cap["name"])

        top_caps = capabilities[:5]

        results_table.append([
            file_name,
            entropy_hits,
            suspicious_imports,
            "\n".join(top_caps) if top_caps else "No major capabilities flagged."
        ])

    # 6. Summary Layout Reports

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