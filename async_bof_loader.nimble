# Package

version       = "0.1.0"
author        = "Jakob Friedl"
description   = "Async BOF loader implemented as a post-ex DLL"
license       = "BSD-3-Clause"
srcDir        = "src"

# Build task

task dll, "Build DLL":
    exec "nim c --os:windows --cpu:amd64 --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc --mm:none --app:lib --nomain -d:danger --passL:\"-static-libgcc\" -o:dist/async-bof.dll src/main.nim"

# Dependencies
requires "nim >= 2.2.8"
requires "winim >= 3.9.4"