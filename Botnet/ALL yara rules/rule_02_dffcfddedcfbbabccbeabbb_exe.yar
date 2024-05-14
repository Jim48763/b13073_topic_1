rule dffcfddedcfbbabccbeabbb_exe {
strings:
        $s1 = "Lazexohex xewiset gepes"
        $s2 = "=N4#z$d(Q_}"
        $s3 = "d$()\"P21+:"
        $s4 = "VarFileInfo"
        $s5 = "$,9W|qbmvT%"
        $s6 = "=8CI/ykf7o*"
        $s7 = "G!|g)b:8C6{"
        $s8 = "\"rw*uPIEn3"
        $s9 = "TjKg0 uiX`!"
        $s10 = "`local vftable'"
        $s11 = "bomgpiaruci.iwa"
        $s12 = "GetModuleHandleW"
        $s13 = "TerminateProcess"
        $s14 = "GetCurrentThreadId"
        $s15 = "H2`izW:xGo44"
        $s16 = "$($G!\"+e:Vh"
        $s17 = "SetEndOfFile"
        $s18 = "UzO>D}v\\c+*"
        $s19 = "GetTickCount"
        $s20 = "SetConsoleCursorPosition"
condition:
    uint16(0) == 0x5a4d and filesize < 1191KB and
    4 of them
}
    
