VOLATILITY_PATH = "vol.py"
MEMORY_IMAGE = "memory.raw"

YARA_RULES = "rules/malware_rules.yar"

DUMP_DIR = "dumps"

VOL_PLUGINS = [
    "windows.pslist",
    "windows.malfind",
    "windows.dlllist",
    "windows.netscan"
]