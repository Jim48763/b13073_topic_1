rule fabbdcaabefbfeddeefaafeebab_exe {
strings:
        $s1 = "gethostbyname"
        $s2 = "Process32Next"
        $s3 = "MethCallEngine"
        $s4 = "DllFunctionCall"
        $s5 = "RtlMoveMemory"
        $s6 = "GetProcAddress"
        $s7 = "CreateShortcut"
        $s8 = "NMAmNkwK53"
        $s9 = "VS_VERSION_INFO"
        $s10 = "CompanyName"
        $s11 = "LoadLibraryW"
        $s12 = "MSVBVM60.DLL"
        $s13 = "TargetPath"
        $s14 = "IconLocation"
        $s15 = "vGHop56o7po667"
        $s16 = "NsetPs&nPs"
        $s17 = "BobCYXzh"
        $s18 = "kernel32"
        $s19 = "VB5!6&*"
        $s20 = "wsock32"
condition:
    uint16(0) == 0x5a4d and filesize < 81KB and
    4 of them
}
    
