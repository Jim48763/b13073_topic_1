rule acafbfccedbefeeadba_exe {
strings:
        $s1 = "gethostbyname"
        $s2 = "Process32Next"
        $s3 = "MethCallEngine"
        $s4 = "DllFunctionCall"
        $s5 = "RtlMoveMemory"
        $s6 = "GetProcAddress"
        $s7 = "CreateShortcut"
        $s8 = "VS_VERSION_INFO"
        $s9 = "LoadLibraryW"
        $s10 = "MSVBVM60.DLL"
        $s11 = "TargetPath"
        $s12 = "NsetPs&nPs?|Ps"
        $s13 = "IconLocation"
        $s14 = "akTSGsTqp"
        $s15 = "~eSi'TUf"
        $s16 = "AVjWIkGF"
        $s17 = "kernel32"
        $s18 = "s<# M+)"
        $s19 = "vYcq=Fo"
        $s20 = "%45.wAg"
condition:
    uint16(0) == 0x5a4d and filesize < 53KB and
    4 of them
}
    
