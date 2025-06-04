import os
import sys
import pefile
import multiprocessing
import csv

def find_exes(drive: str) -> list[str]:
    exe_files = []
    for root, _, files in os.walk(drive, topdown=True):
        for file in files:
            if file.lower().endswith('.exe'):
                exe_files.append(os.path.join(root, file))

    return exe_files

def is_dotnet_core(exe: str) -> bool:
    res = {"bin": exe, "dotnet_core": False, "module": None}

    try:
        pe = pefile.PE(exe)
        pe.parse_data_directories()

        dotnet_core_modules = (b"mscoree.dll", b"coreclr.dll", b"system.private.corelib.dll")

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.lower() in dotnet_core_modules:
                # print(f"Found: {exe} ({entry.dll.decode('utf-8')})")
                res["dotnet_core"] = True
                res["module"] = entry.dll.decode('utf-8')
                return res
    except:
        return res

    # Use pe.OPTIONAL_HEADER.DATA_DIRECTORY?

    return res

def main() -> int:
    print("Searching for exes")
    exes = find_exes("C:\\")

    print("Inspecting exes found")
    res = []
    with multiprocessing.Pool(multiprocessing.cpu_count()) as p:
        res = p.map(is_dotnet_core, exes)

    with open("dotnet_core_exes.csv", "w") as f:
        writer = csv.DictWriter(f, fieldnames=('bin', 'dotnet_core', 'module'))
        writer.writeheader()
        for item in res:
            if not item["dotnet_core"]:
                continue

            writer.writerow(item)

    return 0

if __name__ == "__main__":
    sys.exit(main())
