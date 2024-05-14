rule Ransomware_Mischa_v_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "cross device link"
        $s4 = "english-caribbean"
        $s5 = "SetDefaultDllDirectories"
        $s6 = "executable format error"
        $s7 = "result out of range"
        $s8 = "directory not empty"
        $s9 = "CoInitializeEx"
        $s10 = "@WM_ATLGETHOST"
        $s11 = "OleLockRunning"
        $s12 = "invalid string position"
        $s13 = "operation canceled"
        $s14 = "getHostDescription"
        $s15 = ".?AVbad_cast@std@@"
        $s16 = "LC_MONETARY"
        $s17 = "_WriteLog@4"
        $s18 = "english-jamaica"
        $s19 = "`local vftable'"
        $s20 = "getScreenBounds"
condition:
    uint16(0) == 0x5a4d and filesize < 284KB and
    4 of them
}
    
