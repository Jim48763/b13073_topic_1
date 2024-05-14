rule acddebcccabfabeceacdfdfdbddbdc_exe {
strings:
        $s1 = "cross device link"
        $s2 = "english-caribbean"
        $s3 = "CreateThreadpoolTimer"
        $s4 = "`vector destructor iterator'"
        $s5 = "SetDefaultDllDirectories"
        $s6 = "CUGOROZOTAHUJAMIJURUKUKI"
        $s7 = "CreateIoCompletionPort"
        $s8 = "executable format error"
        $s9 = "directory not empty"
        $s10 = "result out of range"
        $s11 = "Runtime Error!"
        $s12 = "invalid string position"
        $s13 = "Locitotebosini musebu"
        $s14 = "operation canceled"
        $s15 = "LC_MONETARY"
        $s16 = "english-jamaica"
        $s17 = "`local vftable'"
        $s18 = "spanish-venezuela"
        $s19 = "chinese-singapore"
        $s20 = "SetFilePointerEx"
condition:
    uint16(0) == 0x5a4d and filesize < 298KB and
    4 of them
}
    
