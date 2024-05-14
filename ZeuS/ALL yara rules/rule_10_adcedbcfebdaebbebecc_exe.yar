rule adcedbcfebdaebbebecc_exe {
strings:
        $s1 = "Y#:T`ykB0%O"
        $s2 = "\"I x+m0Vwb"
        $s3 = "LoadStringA"
        $s4 = "GetKeyboardType"
        $s5 = "GetThreadLocale"
        $s6 = "WinHttpCreateUrl"
        $s7 = "GetModuleHandleA"
        $s8 = "GetSystemPaletteEntries"
        $s9 = "GetCurrentThreadId"
        $s10 = "GetLocalTime"
        $s11 = "SetEndOfFile"
        $s12 = "GetTickCount"
        $s13 = "J/JUacwyg\\{K"
        $s14 = "IsBadWritePtr"
        $s15 = "FormatMessageA"
        $s16 = "LoadLibraryExA"
        $s17 = "InterlockedDecrement"
        $s18 = "RegOpenKeyExA"
        $s19 = "GetDeviceCaps"
        $s20 = "VirtualProtect"
condition:
    uint16(0) == 0x5a4d and filesize < 3833KB and
    4 of them
}
    
