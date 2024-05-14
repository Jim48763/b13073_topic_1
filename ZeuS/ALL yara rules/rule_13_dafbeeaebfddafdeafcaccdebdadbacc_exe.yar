rule dafbeeaebfddafdeafcaccdebdadbacc_exe {
strings:
        $s1 = "LoadStringA"
        $s2 = "GetKeyboardType"
        $s3 = "GetThreadLocale"
        $s4 = "GetModuleHandleA"
        $s5 = "GetSystemPaletteEntries"
        $s6 = "GetCurrentThreadId"
        $s7 = "GetLocalTime"
        $s8 = "SetEndOfFile"
        $s9 = "GetTickCount"
        $s10 = "FormatMessageA"
        $s11 = "LoadLibraryExA"
        $s12 = "InterlockedDecrement"
        $s13 = "GetDeviceCaps"
        $s14 = "RegOpenKeyExA"
        $s15 = "VirtualProtect"
        $s16 = "]fvF6[<pSU"
        $s17 = "L?@1_pFQj0"
        $s18 = "xc\"er'Fil"
        $s19 = "GetCurrentProcess"
        $s20 = "ExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 3685KB and
    4 of them
}
    
