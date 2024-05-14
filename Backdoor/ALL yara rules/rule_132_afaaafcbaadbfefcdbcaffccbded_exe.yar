rule afaaafcbaadbfefcdbcaffccbded_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "CreateThreadpoolTimer"
        $s4 = "SetDefaultDllDirectories"
        $s5 = "RpcBindingToStringBindingA"
        $s6 = "SetConsoleCtrlHandler"
        $s7 = "LC_MONETARY"
        $s8 = "english-jamaica"
        $s9 = "InternetTimeFromSystemTime"
        $s10 = "spanish-venezuela"
        $s11 = "TerminateProcess"
        $s12 = "waveOutSetVolume"
        $s13 = "SetFilePointerEx"
        $s14 = "SetThreadStackGuarantee"
        $s15 = "EnterCriticalSection"
        $s16 = "south-africa"
        $s17 = "OLEAUT32.dll"
        $s18 = "XHxXhy>(tOJc"
        $s19 = "ImmDisableIME"
        $s20 = "trinidad & tobago"
condition:
    uint16(0) == 0x5a4d and filesize < 430KB and
    4 of them
}
    
