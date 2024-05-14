rule dffcdfabfdecafebdddecdfde_exe {
strings:
        $s1 = "Lazexohex xewiset gepes"
        $s2 = "soxapexadiwisejipokoh"
        $s3 = "7iG6\"Q[FZ{"
        $s4 = "9Y6VB0gfO<)"
        $s5 = "!cbjq\"Ir2G"
        $s6 = "69&2HrdPnBA"
        $s7 = "VarFileInfo"
        $s8 = "L6pk:`Rr~Ei"
        $s9 = "`local vftable'"
        $s10 = "bomgpiaruci.iwa"
        $s11 = "GetModuleHandleW"
        $s12 = "TerminateProcess"
        $s13 = "GetCurrentThreadId"
        $s14 = "GetTickCount"
        $s15 = "uA\\l:y)'R$z"
        $s16 = "SetConsoleCursorPosition"
        $s17 = "TGGb@i:TuLq]6"
        $s18 = "Unknown exception"
        $s19 = "ptwotabumoguri"
        $s20 = "SetHandleCount"
condition:
    uint16(0) == 0x5a4d and filesize < 1725KB and
    4 of them
}
    
