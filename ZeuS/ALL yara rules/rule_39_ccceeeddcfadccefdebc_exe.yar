rule ccceeeddcfadccefdebc_exe {
strings:
        $s1 = "acmDriverDetailsA"
        $s2 = "CreateColorTransformW"
        $s3 = "`vector destructor iterator'"
        $s4 = "        <td valign=\"top\">"
        $s5 = "WNetAddConnection2A"
        $s6 = "Directory not empty"
        $s7 = "RegSetValueExA"
        $s8 = "Runtime Error!"
        $s9 = "invalid string position"
        $s10 = "accDoDefaultAction"
        $s11 = "GetConsoleOutputCP"
        $s12 = "No child processes"
        $s13 = "Link Source"
        $s14 = "`local vftable'"
        $s15 = "GetThreadLocale"
        $s16 = "&iacute; a snadn"
        $s17 = "TerminateProcess"
        $s18 = "DispatchMessageA"
        $s19 = "GetModuleHandleA"
        $s20 = "Operation not permitted"
condition:
    uint16(0) == 0x5a4d and filesize < 449KB and
    4 of them
}
    
