# GhiDump

## Introduction
**GhiDump** is an open source plugin for Ghidra. The main purpose is to export the auto-analysis results to Protocol Buffers.

It was born primarily as a project for my degree course in Computer Engineering.

## Usage

1. Open Ghidra
2. `File > Install Extensions... > Add extension`
3. Select `GhiDump.zip`
4. Restart Ghidra
5. Open the Script Manager and check the GhiDump script
6. Find GhiDump shortcut in `Tools > GhiDump`

GhiDumps are in `/home/$USER/GhiDumps` or `$GHIDRA_DIR/GhiDumps` depending on Ghidra directory.

If you want to run GhiDump in headless mode, import the repo as a project in Eclipse, edit run configuration and make sure you insert the arguments such as

    /my/project/location myProjectName -import /marvellous/executables/dir -postScript GhiDump.java -scriptPath "/path/to/GhiDump/src"

## Output
Exported Protocol Buffers in `GhiDumps` folder follow definitions in `proto` folders. There's one big exported .pb with:
 - `symbols` contains every symbol processed by Ghidra, with XREFS and much more
 - `functions` contains every function encountered divided into basic blocks
 - `data` contains every data reference and value in `.data` and `.bss` sections
 - `metadata` contains metadata about the binary, e.g. architecture, name, etc..
 - `segments` contains starting address, ending address and length in bytes of memory blocks
 
## Results
This repository contains a tarball with exported protocol buffers based on amd64, i386, arm and win32 binaries of GNU Utilities like binutils, coreutils, etc..

## License
[GPLv3](https://github.com/r0metheus/GhiDump/blob/master/LICENSE)
