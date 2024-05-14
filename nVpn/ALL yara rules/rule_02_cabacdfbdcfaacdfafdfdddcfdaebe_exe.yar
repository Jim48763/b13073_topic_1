rule cabacdfbdcfaacdfafdfdddcfdaebe_exe {
strings:
        $s1 = "ProductName"
        $s2 = "CYxKXs7ik9Q"
        $s3 = "VarFileInfo"
        $s4 = "_CorExeMain"
        $s5 = "1dBFER4I7ur"
        $s6 = "Cx2wCQ2NLE5y.Cm"
        $s7 = "FileDescription"
        $s8 = "GetExportedTypes"
        $s9 = "DebuggerHiddenAttribute"
        $s10 = "sW5IAdWAYWgEwd5EUhA"
        $s11 = "vX2IgqccyuvIcaXthI"
        $s12 = "Dictionary`2"
        $s13 = "Durbanville1"
        $s14 = "get_CurrentThread"
        $s15 = "System.Resources"
        $s16 = "qL1V2R0rG0vRe"
        $s17 = "StringBuilder"
        $s18 = "get_ManagedThreadId"
        $s19 = "GeneratedCodeAttribute"
        $s20 = "8DsM2vucusPQwDP"
condition:
    uint16(0) == 0x5a4d and filesize < 988KB and
    4 of them
}
    
