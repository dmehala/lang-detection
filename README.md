To build:
```sh
# Configure
cmake -B build .

# Build
cmake --build build -j

# Binaries generated
ls build
PS C:\workspace\lang-detection> ls build


    Directory: C:\workspace\lang-detection\build


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         4/25/2025  10:25 AM                CMakeFiles
-a----         4/25/2025  12:02 PM            532 .ninja_deps
-a----         4/25/2025  12:02 PM           4733 .ninja_log
-a----         4/25/2025  10:25 AM          37310 build.ninja
-a----         4/25/2025  10:25 AM          13975 CMakeCache.txt
-a----         4/25/2025  10:25 AM           1435 cmake_install.cmake
-a----         4/25/2025  10:25 AM         150528 Injector.exe   <==== inject the dll
-a----         4/25/2025  10:25 AM        1346560 Injector.ilk
-a----         4/25/2025  10:25 AM        2224128 Injector.pdb
-a----         4/25/2025  12:02 PM         152576 Mylib.dll      <==== dll to inject
-a----         4/25/2025  12:02 PM        2439160 Mylib.ilk
-a----         4/25/2025  12:02 PM        3248128 Mylib.pdb
-a----         4/25/2025  10:25 AM          54784 Simple.exe     <==== bin example
-a----         4/25/2025  10:25 AM         602248 Simple.ilk
-a----         4/25/2025  10:25 AM        1347584 Simple.pdb
```

Usage:
```sh
python

./build/Injector.exe $pwd\build\Mylib.dll <PYTHON_PID>
```
