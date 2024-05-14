rule cadcdeaffecbaccbbdbcdadbeddc_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "english-caribbean"
        $s4 = " exceeds the maximum of "
        $s5 = ": message length of "
        $s6 = "Directory not empty"
        $s7 = "invalid string position"
        $s8 = "boost::filesystem::remove"
        $s9 = "No child processes"
        $s10 = "LC_MONETARY"
        $s11 = "ThisObject:"
        $s12 = "english-jamaica"
        $s13 = "`local vftable'"
        $s14 = "DeviceIoControl"
        $s15 = "spanish-venezuela"
        $s16 = "GetShortPathNameA"
        $s17 = "RemoveDirectoryW"
        $s18 = "TerminateProcess"
        $s19 = "GetModuleHandleW"
        $s20 = "Operation not permitted"
condition:
    uint16(0) == 0x5a4d and filesize < 752KB and
    4 of them
}
    
