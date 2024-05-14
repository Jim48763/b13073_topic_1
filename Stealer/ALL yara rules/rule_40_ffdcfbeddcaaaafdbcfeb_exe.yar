rule ffdcfbeddcaaaafdbcfeb_exe {
strings:
        $s1 = "GetModuleHandleA"
        $s2 = "VirtualProtect"
        $s3 = "GetCurrentThread"
        $s4 = "GetProcAddress"
        $s5 = "VirtualAlloc"
        $s6 = "vD E(#@(gP"
        $s7 = "msimg32.dll"
        $s8 = "VirtualFree"
        $s9 = "LoadLibraryA"
        $s10 = "shlwapi.dll"
        $s11 = "comctl32.dll"
        $s12 = "kernel32.dll"
        $s13 = "DllInitialize"
        $s14 = "Q\"T@ 4@("
        $s15 = "StrChrNIW"
        $s16 = "(\"@*j@*j@"
        $s17 = "@(FA(DQ(d"
        $s18 = "ole32.dll"
        $s19 = "T*2P\"NA"
        $s20 = "lstrcmpA"
condition:
    uint16(0) == 0x5a4d and filesize < 438KB and
    4 of them
}
    
