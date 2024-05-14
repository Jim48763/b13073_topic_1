rule fadbcffdbbceecccea_dll {
strings:
        $s1 = "winspool.drv"
        $s2 = "GetTickCount"
        $s3 = "EndDocPrinter"
        $s4 = "Greater Manchester1"
        $s5 = "VirtualProtect"
        $s6 = "Dublin1E0C"
        $s7 = "GetProcessId"
        $s8 = "Jersey City1"
        $s9 = "GetProcAddress"
        $s10 = "ReplaceTextA"
        $s11 = "VirtualAlloc"
        $s12 = "GetVersion"
        $s13 = "LoadLibraryA"
        $s14 = "New Jersey1"
        $s15 = "<<<Obsolete>>"
        $s16 = "kernel32.dll"
        $s17 = "comctl32.dll"
        $s18 = "&T*)U\"QQ\""
        $s19 = "301231235959Z0|1"
        $s20 = "\\@ \"D(OP"
condition:
    uint16(0) == 0x5a4d and filesize < 505KB and
    4 of them
}
    
