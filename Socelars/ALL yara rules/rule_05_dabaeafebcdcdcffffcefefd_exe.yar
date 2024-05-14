rule dabaeafebcdcdcffffcefefd_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "cross device link"
        $s4 = "english-caribbean"
        $s5 = "executable format error"
        $s6 = "result out of range"
        $s7 = "directory not empty"
        $s8 = "err : securepref not found"
        $s9 = "CoInitializeEx"
        $s10 = "RegSetValueExA"
        $s11 = "invalid string position"
        $s12 = "invalid distance code"
        $s13 = "RtlNtStatusToDosError"
        $s14 = "operation canceled"
        $s15 = "/Home/Index/lkdinl"
        $s16 = "LC_MONETARY"
        $s17 = "english-jamaica"
        $s18 = "`local vftable'"
        $s19 = "DeviceIoControl"
        $s20 = "Process32FirstW"
condition:
    uint16(0) == 0x5a4d and filesize < 546KB and
    4 of them
}
    
