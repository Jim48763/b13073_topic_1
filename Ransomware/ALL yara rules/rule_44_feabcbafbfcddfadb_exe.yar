rule feabcbafbfcddfadb_exe {
strings:
        $s1 = "sc config browser"
        $s2 = "AES Decrypt"
        $s3 = ".db-journal"
        $s4 = "vssadmin list shadows"
        $s5 = "`local vftable'"
        $s6 = "Enumerated type"
        $s7 = "TamperProtectione"
        $s8 = "TerminateProcess"
        $s9 = "SetFilePointerEx"
        $s10 = "SetEndOfFile"
        $s11 = "src/pk/pkcs1/pkcs_1_mgf1.c"
        $s12 = "GetSystemInfo"
        $s13 = "HideSCAHealth"
        $s14 = "MapViewOfFile"
        $s15 = "sc stop MySQL"
        $s16 = ".flexolibrary"
        $s17 = "octets != NULL"
        $s18 = "LoadLibraryExW"
        $s19 = "CorExitProcess"
        $s20 = "Octetstring type"
condition:
    uint16(0) == 0x5a4d and filesize < 402KB and
    4 of them
}
    
