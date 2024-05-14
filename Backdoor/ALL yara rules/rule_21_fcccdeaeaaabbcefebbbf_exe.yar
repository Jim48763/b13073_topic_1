rule fcccdeaeaaabbcefebbbf_exe {
strings:
        $s1 = "GetModuleHandleA"
        $s2 = "InitializeCriticalSection"
        $s3 = "GetProcessHeap"
        $s4 = "AsyncCreate"
        $s5 = "KERNEL32.dll"
        $s6 = "GetProcAddress"
        $s7 = "DllRegisterServer"
        $s8 = "VirtualAlloc"
        $s9 = "VirtualFree"
        $s10 = "TlsGetValue"
        $s11 = "LoadLibraryA"
        $s12 = "GetSystemTime"
        $s13 = "GetLastError"
        $s14 = "D$$;D$0s*H"
        $s15 = "HeapAlloc"
        $s16 = "HeapFree"
        $s17 = "`.rdata"
        $s18 = "D$Hk@P"
        $s19 = "9D$pr"
        $s20 = "L$(H+"
condition:
    uint16(0) == 0x5a4d and filesize < 287KB and
    4 of them
}
    
