import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

VOLATILITY_PATH = os.path.normpath(r"C:\Users\DSU\OneDrive - Dakota State University\Documents\GitHub\Mem-Triag\Mem-Triage\volatility3\volatility3\vol.py")
CAPA_PATH = r"capa"

VOL_PLUGINS = [
    "windows.pslist",
    "windows.psscan",
    "windows.malfind",
    "windows.dlllist",
    "windows.netscan"
]

DUMP_PLUGINS = [
    "windows.malfind"
]

def get_unique_dump_dir():
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique_dir = os.path.join(BASE_DIR, f"dumps_{timestamp}")
    os.makedirs(unique_dir, exist_ok=True)
    return unique_dir