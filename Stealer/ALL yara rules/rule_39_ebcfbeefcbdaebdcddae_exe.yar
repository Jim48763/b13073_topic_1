rule ebcfbeefcbdaebdcddae_exe {
strings:
        $s1 = "!RPYMT&\"&MY#!XMW!R:&&\"!"
        $s2 = "mENpw}vnj9T|jj"
        $s3 = "Chpotihkchr<&H"
        $s4 = "invalid string position"
        $s5 = "I?[~vxrp{/s"
        $s6 = "z)5<.-;(?&7"
        $s7 = "`local vftable'"
        $s8 = "SetFilePointerEx"
        $s9 = "TerminateProcess"
        $s10 = "Eqpvgpv/V{rg<\"c7gggg7(((7gggg7d"
        $s11 = "GetCurrentThreadId"
        $s12 = "dyr%xzg4hdG]"
        $s13 = ";.=885{azdt|"
        $s14 = ".?AVImageC@@"
        $s15 = "FindFirstFileExW"
        $s16 = "I?vQYPMR^KVPQ"
        $s17 = "N}}]||yiN}!}`TUIX"
        $s18 = "Unknown exception"
        $s19 = "CorExitProcess"
        $s20 = "LoadLibraryExW"
condition:
    uint16(0) == 0x5a4d and filesize < 342KB and
    4 of them
}
    
