rule dfbdebaffbfaef_exe {
strings:
        $s1 = "EnterCriticalSection"
        $s2 = "HeapDestroy"
        $s3 = "KERNEL32.dll"
        $s4 = "ADVAPI32.dll"
        $s5 = "GetProcAddress"
        $s6 = "GetUserNameA"
        $s7 = "VirtualAlloc"
        $s8 = "VirtualFree"
        $s9 = "HeapReAlloc"
        $s10 = "CloseHandle"
        $s11 = "LoadLibraryA"
        $s12 = ".rdata$zzzdbg"
        $s13 = "CreateEventA"
        $s14 = "WS2_32.dll"
        $s15 = "CreateThread"
        $s16 = "0A_A^A\\_^]["
        $s17 = "HeapCreate"
        $s18 = "UVWATAUAVAWH"
        $s19 = "lstrcpyA"
        $s20 = "D$ Iphl#"
condition:
    uint16(0) == 0x5a4d and filesize < 17KB and
    4 of them
}
    
