rule cacfbbcbafaaaeeefecdbeced_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "b6HLj6654'E<c046p"
        $s4 = "1,6%1_1r1z0Y4,eAf"
        $s5 = "4Te>f69AfVaQfQf@b"
        $s6 = "SHRegCreateUSKeyW"
        $s7 = "CreateColorTransformA"
        $s8 = "`vector destructor iterator'"
        $s9 = "Runtime Error!"
        $s10 = "81c204beaff93f=a2f4f3bb"
        $s11 = "SetConsoleCtrlHandler"
        $s12 = "7>8f661>181c004feafc;"
        $s13 = "_2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c00"
        $s14 = "DK1%Y[AWC]b"
        $s15 = "6eAWR]10IC@"
        $s16 = "BSpEHVR1UCA"
        $s17 = "63804b@ja,."
        $s18 = "ZMTfbYxXE]V"
        $s19 = "izTXVLYc|Q@"
        $s20 = "LC_MONETARY"
condition:
    uint16(0) == 0x5a4d and filesize < 344KB and
    4 of them
}
    
