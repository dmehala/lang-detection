import os
import argparse
import struct
import sys
import pefile
import multiprocessing
import csv
import typing

def find_exes(drive: str) -> list[str]:
    exe_files = []
    for root, _, files in os.walk(drive, topdown=True):
        for file in files:
            if file.lower().endswith('.exe'):
                exe_files.append(os.path.join(root, file))

    return exe_files

# def is_dotnet_core(exe: str) -> bool:
#     res = {"bin": exe, "dotnet_core": False, "module": None}
#
#     try:
#         pe = pefile.PE(exe)
#         pe.parse_data_directories()
#
#         dotnet_core_modules = (b"mscoree.dll", b"coreclr.dll", b"system.private.corelib.dll")
#
#         for entry in pe.DIRECTORY_ENTRY_IMPORT:
#             if entry.dll.lower() in dotnet_core_modules:
#                 # print(f"Found: {exe} ({entry.dll.decode('utf-8')})")
#                 res["dotnet_core"] = True
#                 res["module"] = entry.dll.decode('utf-8')
#                 return res
#     except:
#         return res
#
#     # Use pe.OPTIONAL_HEADER.DATA_DIRECTORY?
#
#     return res

def search_dotnet_in_PE(exe):
    try:
        pe = pefile.PE(exe)

        # Ensure the PE file has .NET header
        com_header = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]  #< 14 = IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
        if com_header.VirtualAddress == 0:
            return None

        def read_dword(pe, addr):
            return struct.unpack("<L", pe.get_data(addr, 4))[0]

        # Search from the metadata entry from the .NET header.
        metadata_rva = read_dword(pe, com_header.VirtualAddress + 8)
        # metadata_size = read_dword(pe, com_header.VirtualAddress + 12)

        # print(f"Metadata RVA: {metadata_rva:x}")
        # print(f"Metadata Size: {metadata_size:0x}")

        # Reading Metadata header
        version_length = read_dword(pe, metadata_rva + 12)
        version_str = pe.get_data(metadata_rva + 16, version_length)

        # print(f"Version: {version_str}")
        return version_str.decode('unicode_escape')
    except:
        return None

def search_dotnet_core(exe):
    # 8 bytes represent the bundle header-offset
    # Zero for non-bundle apphosts (default).
    # we ignore this because for selfcontained this might be not zero
    # 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    # 32 bytes represent the bundle signature: SHA-256 for ".net core bundle"
    bundle_header = bytes((
        0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
        0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae
    ))

    # as the header does not match on the dotnet executable itself we use the following
    # matcher
    # https://github.com/dotnet/runtime/blob/37b1764e19aceaa545d8433c490b850538b8905a/src/native/corehost/hostmisc/utils.cpp#L503
    # skipping the first byte as it's value can change
    var_placeholder = bytes((
        0x33, 0x38, 0x63, 0x63, 0x38, 0x32, 0x37, 0x2d, 0x65, 0x33, 0x34, 0x66, 0x2d, 0x34, 0x34, 0x35,
        0x33, 0x2d, 0x39, 0x64, 0x66, 0x34, 0x2d, 0x31, 0x65, 0x37, 0x39, 0x36, 0x65, 0x39, 0x66, 0x31,
    ))

    with open(exe, 'rb') as f:
        # TODO: avoid reading the whole file
        data = f.read(4098)
        if data.find(bundle_header) != 1 or data.find(var_placeholder) != 1:
            return True

    return False

def is_dotnet(exe: str) -> dict[str, typing.Any]:
    print(exe)

    res = {"bin": exe, "framework": "", "version": ""}

    dotnet_version = search_dotnet_in_PE(exe)
    if dotnet_version:
        res["version"] = dotnet_version
        res["framework"] = ".NET Framework"
        return res

    if search_dotnet_core(exe):
        res["version"] = ""
        res["framework"] = ".NET CORE"

    return res

# def main() -> int:
#     exe = sys.argv[1]
#     print(is_dotnet(exe))
#     return 0

def main() -> int:
    DEFAULT_DRIVE = "C:\\"
    parser = argparse.ArgumentParser()
    parser.add_argument("drive", help="Drive to search for exes", default=DEFAULT_DRIVE)

    args = parser.parse_args()

    print(f"Searching for exes in {args.drive}")
    exes = find_exes(args.drive)

    print("Inspecting exes found")
    res = []
    with multiprocessing.Pool(multiprocessing.cpu_count()) as p:
        res = p.map(is_dotnet, exes)

    with open("dotnet_core_exes.csv", "w") as f:
        writer = csv.DictWriter(f, fieldnames=('bin', 'dotnet_version'))
        writer.writeheader()
        for item in res:
            if not item["is_dotnet"]:
                continue

            writer.writerow({"bin": item["bin"], "dotnet_version": item["version"]})

    return 0

if __name__ == "__main__":
    sys.exit(main())
