rule ffadcbaecbccebaeefcbcdcea_exe {
strings:
        $s1 = "GetCurrentThreadId"
        $s2 = "VirtualProtect"
        $s3 = "GetCurrentProcess"
        $s4 = "GetProcAddress"
        $s5 = "VirtualAlloc"
        $s6 = "InitCommonControls"
        $s7 = "ZE\"(@ TP("
        $s8 = "VirtualFree"
        $s9 = "msimg32.dll"
        $s10 = "LoadLibraryA"
        $s11 = "OleInitialize"
        $s12 = "comctl32.dll"
        $s13 = "kernel32.dll"
        $s14 = ">P(tD(~E(~A"
        $s15 = "E(<Q(6A(vA(^"
        $s16 = "Q\"T@ 4@("
        $s17 = "(\"@*j@*j@"
        $s18 = "P(LP(lD(DD(d"
        $s19 = "ole32.dll"
        $s20 = "PQRVW=<)"
condition:
    uint16(0) == 0x5a4d and filesize < 381KB and
    4 of them
}
    
