rule Trojan_ColorBug_exe {
strings:
        $s1 = "LoadStringA"
        $s2 = "WindowFrame"
        $s3 = "GetKeyboardType"
        $s4 = "GetThreadLocale"
        $s5 = "GetModuleHandleA"
        $s6 = "Division by zero"
        $s7 = "InitializeCriticalSection"
        $s8 = "GetCurrentThreadId"
        $s9 = "EInvalidCast"
        $s10 = "SetEndOfFile"
        $s11 = "FPUMaskValue"
        $s12 = "EOutOfMemory"
        $s13 = "THandleStream"
        $s14 = "File not found"
        $s15 = "FormatMessageA"
        $s16 = "LoadLibraryExA"
        $s17 = "Invalid filename"
        $s18 = "RegCreateKeyExA"
        $s19 = "ButtonAlternateFace"
        $s20 = "Read beyond end of file"
condition:
    uint16(0) == 0x5a4d and filesize < 58KB and
    4 of them
}
    
