import winim/lean
import macros

#[
    Compile-time string encryption using simple XOR
    This is done to hide sensitive strings in the binary
    Original: https://github.com/S3cur3Th1sSh1t/nim-strenc/blob/main/src/strenc.nim
]#

func djb2(s: string): int {.compileTime.} =
    result = 5381
    for c in s:
        result = ((result shl 5) +% result) +% ord(c)
    result = result and 0x7FFFFFFF

var key {.compileTime.}: int = djb2(CompileTime & CompileDate)

proc calculate*(str: string, key: int): string {.noinline.} =
    var k = key
    result = str
    for i in 0 ..< result.len:
        var b = byte(result[i])
        for f in [0, 8, 16, 24]:
            b = b xor uint8((k shr f) and 0xFF)
        k = k +% 1
        result[i] = char(b)

macro protect*(str: untyped): untyped =
    var encStr = calculate($str, key)
    result = quote do:
        calculate(`encStr`, `key`)

    # Alternate the XOR key using the FNV prime (1677619)
    key = (key *% 1677619) and 0x7FFFFFFF

# Convert Windows API error to readable value
# https://learn.microsoft.com/de-de/windows/win32/api/winbase/nf-winbase-formatmessage
proc getError*(errorCode: DWORD): string =
    var msg = newWString(512)
    discard FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM or FORMAT_MESSAGE_IGNORE_INSERTS, NULL, errorCode, cast[DWORD](MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)), msg, cast[DWORD](msg.len()), NULL)
    msg.nullTerminate()
    var s = $msg
    while s.len > 0 and (s[^1] == '\n' or s[^1] == '\r' or s[^1] == ' '):
        s.setLen(s.len - 1)
    return s & " (" & $errorCode & ")"

# Convert NTSTATUS to readable value 
# https://ntdoc.m417z.com/rtlntstatustodoserror
type 
    RtlNtStatusToDosError = proc(status: NTSTATUS): DWORD {.stdcall.}

proc getNtError*(status: NTSTATUS): string = 
    let pRtlNtStatusToDosError = cast[RtlNtStatusToDosError](GetProcAddress(GetModuleHandleA(protect("ntdll")), protect("RtlNtStatusToDosError")))
    let errorCode = pRtlNtStatusToDosError(status)
    return getError(errorCode) 
