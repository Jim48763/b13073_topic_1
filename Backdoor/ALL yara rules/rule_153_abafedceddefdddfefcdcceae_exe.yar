rule abafedceddefdddfefcdcceae_exe {
strings:
        $s1 = " 2\"/$IVcHZ"
        $s2 = "k>GTan%K}Q^"
        $s3 = "Vcp}bIhNAB]"
        $s4 = "X{IVcp}uh[N"
        $s5 = "%\"Z,;FS`EJ"
        $s6 = "\"KyZ]7?-Cw"
        $s7 = "\"byDY1)]jw"
        $s8 = "RP\"-<IV}*8"
        $s9 = "`8P\"/<IVAu"
        $s10 = "~aQ$b>KX=,9"
        $s11 = "!\"g/?IVcYJ"
        $s12 = "GetModuleHandleW"
        $s13 = "TerminateProcess"
        $s14 = "WriteProcessMemory"
        $s15 = "GetCurrentThreadId"
        $s16 = "~\"T -:GTan{"
        $s17 = "GetTickCount"
        $s18 = "SetHandleCount"
        $s19 = "    </security>"
        $s20 = "GetSystemTimeAsFileTime"
condition:
    uint16(0) == 0x5a4d and filesize < 557KB and
    4 of them
}
    
