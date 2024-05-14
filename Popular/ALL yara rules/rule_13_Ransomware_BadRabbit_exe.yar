rule Ransomware_BadRabbit_exe {
strings:
        $s1 = "invalid distance code"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "FileDescription"
        $s5 = "TerminateProcess"
        $s6 = "GetModuleHandleW"
        $s7 = "51=o>g7RxQj="
        $s8 = "Durbanville1"
        $s9 = "invalid window size"
        $s10 = "FlashUtil.exe"
        $s11 = "\\rundll32.exe"
        $s12 = "need dictionary"
        $s13 = "    </security>"
        $s14 = "header crc mismatch"
        $s15 = "Western Cape1"
        $s16 = "%\\4*<b\"]q2-"
        $s17 = "incorrect header check"
        $s18 = "GetProcessHeap"
        $s19 = "LegalTrademarks"
        $s20 = "~MU`?#7\"a"
condition:
    uint16(0) == 0x5a4d and filesize < 436KB and
    4 of them
}
    
