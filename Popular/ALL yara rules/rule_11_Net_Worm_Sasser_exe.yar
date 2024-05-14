rule Net_Worm_Sasser_exe {
strings:
        $s1 = "dynamic link lib"
        $s2 = "OGRAM 1.X0"
        $s3 = "geXtMic_m:m"
        $s4 = " located in the "
        $s5 = "GetProcAddress"
        $s6 = "Entry Point Not"
        $s7 = "rary %s.Qord"
        $s8 = "#tSy`oemSYhS"
        $s9 = "VirtualAlloc"
        $s10 = "VirtualFree"
        $s11 = "LoadLibraryA"
        $s12 = "kernel32.dll"
        $s13 = "wsprintfA"
        $s14 = "%,Xklw3n>"
        $s15 = "V7\\.-p%u"
        $s16 = "The proce"
        $s17 = "I0#\"uc%"
        $s18 = ">cmd.ftp"
        $s19 = "adq!ckj/"
        $s20 = "ageBoxAX"
condition:
    uint16(0) == 0x5a4d and filesize < 20KB and
    4 of them
}
    
