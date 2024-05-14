rule cfacbfebfbfacbbeeffeeffeac_exe {
strings:
        $s1 = "TerminateProcess"
        $s2 = "GetModuleHandleA"
        $s3 = "b~uhlpdr!kui"
        $s4 = "GetThreadContext"
        $s5 = "RtlGetVersion"
        $s6 = "~kisiowkt8plv"
        $s7 = "GetProcessHeap"
        $s8 = "T~pwx@t}pjxX~xl"
        $s9 = "hZd2Q\"u01"
        $s10 = "`cwTqgreaz"
        $s11 = "IsProcessorFeaturePresent"
        $s12 = "GetCurrentThread"
        $s13 = "8?97=5*u09:"
        $s14 = ":Z)fvGNC{2v"
        $s15 = "IsDebuggerPresent"
        $s16 = "KERNEL32.dll"
        $s17 = "VirtualQuery"
        $s18 = "ADVAPI32.dll"
        $s19 = "`vdjjkl~'lgf"
        $s20 = "CryptCreateHash"
condition:
    uint16(0) == 0x5a4d and filesize < 139KB and
    4 of them
}
    
