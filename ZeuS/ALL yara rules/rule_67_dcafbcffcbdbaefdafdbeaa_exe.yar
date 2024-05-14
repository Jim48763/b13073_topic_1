rule dcafbcffcbdbaefdafdbeaa_exe {
strings:
        $s1 = "DeviceIoControl"
        $s2 = "GetModuleHandleA"
        $s3 = "Module32Next"
        $s4 = "GetThreadContext"
        $s5 = "_XcptFilter"
        $s6 = "KERNEL32.dll"
        $s7 = "_adjust_fdiv"
        $s8 = "GetFileAttributesA"
        $s9 = "__getmainargs"
        $s10 = "_controlfp"
        $s11 = "MSVCRT.dll"
        $s12 = "VirtualFree"
        $s13 = "GetStdHandle"
        $s14 = "__setusermatherr"
        $s15 = "GlobalLock"
        $s16 = ")p</sY(j;"
        $s17 = "e1Y_{:s(#"
        $s18 = "l5^)%tS>6"
        $s19 = ":X_Ts)&W0"
        $s20 = "ResetEvent"
condition:
    uint16(0) == 0x5a4d and filesize < 170KB and
    4 of them
}
    
