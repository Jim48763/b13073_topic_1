rule dbabedbaccdbcefefedaddbc_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "GetEnvironmentStrings"
        $s4 = "GetSystemPowerStatus"
        $s5 = "YOSIBALIBINIBUREWEHO"
        $s6 = "CreateIoCompletionPort"
        $s7 = "Directory not empty"
        $s8 = "Runtime Error!"
        $s9 = "A*;1Y%\\c!O\"~"
        $s10 = "invalid string position"
        $s11 = "ios_base::failbit set"
        $s12 = "No child processes"
        $s13 = "SetConsoleOutputCP"
        $s14 = "pJ,B@V)qt;w"
        $s15 = "$B=j~*bsU;>"
        $s16 = "&x3WVOjkR:8"
        $s17 = "CopyFileExA"
        $s18 = "IN5UJGb_K^$"
        $s19 = "_husaberg@4"
        $s20 = "-hdBJ u/,FQ"
condition:
    uint16(0) == 0x5a4d and filesize < 5996KB and
    4 of them
}
    
