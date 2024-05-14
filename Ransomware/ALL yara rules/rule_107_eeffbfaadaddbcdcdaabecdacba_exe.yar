rule eeffbfaadaddbcdcdaabecdacba_exe {
strings:
        $s1 = "cross device link"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "CreateIoCompletionPort"
        $s4 = "executable format error"
        $s5 = "result out of range"
        $s6 = "directory not empty"
        $s7 = "invalid string position"
        $s8 = "operation canceled"
        $s9 = "bUK~9>u5/];"
        $s10 = "pW4.KP$b[\""
        $s11 = "`local vftable'"
        $s12 = "TerminateProcess"
        $s13 = "SetFilePointerEx"
        $s14 = "SetThreadStackGuarantee"
        $s15 = "destination address required"
        $s16 = "SetNamedPipeHandleState"
        $s17 = "connection refused"
        $s18 = "UqqH*\"Q;|yP"
        $s19 = "`vC<@#|C+%BV"
        $s20 = "resource deadlock would occur"
condition:
    uint16(0) == 0x5a4d and filesize < 836KB and
    4 of them
}
    
