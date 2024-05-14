rule aeedcacadfdbdbefcacebfebbe_exe {
strings:
        $s1 = "sc config browser"
        $s2 = "GetConsoleOutputCP"
        $s3 = "AES Decrypt"
        $s4 = ".db-journal"
        $s5 = "`local vftable'"
        $s6 = "Enumerated type"
        $s7 = "TamperProtectione"
        $s8 = "TerminateProcess"
        $s9 = "SetFilePointerEx"
        $s10 = "GetCurrentThreadId"
        $s11 = "SetEndOfFile"
        $s12 = "src/pk/pkcs1/pkcs_1_mgf1.c"
        $s13 = "GetSystemInfo"
        $s14 = "HideSCAHealth"
        $s15 = "MapViewOfFile"
        $s16 = "sc stop MySQL"
        $s17 = ".flexolibrary"
        $s18 = "octets != NULL"
        $s19 = "LoadLibraryExW"
        $s20 = "CorExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 384KB and
    4 of them
}
    
