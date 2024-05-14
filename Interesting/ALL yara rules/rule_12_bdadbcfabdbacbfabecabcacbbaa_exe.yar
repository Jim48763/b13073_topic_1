rule bdadbcfabdbacbfabecabcacbbaa_exe {
strings:
        $s1 = "[ #(@Ib:oz-"
        $s2 = "ZW<Vng62N #"
        $s3 = "*xuIKL-po 3"
        $s4 = "l(T%0{CMgHV"
        $s5 = "VarFileInfo"
        $s6 = "ProductName"
        $s7 = "FileDescription"
        $s8 = "pUef>ISU~{nT"
        $s9 = "VirtualProtect"
        $s10 = "@qJiY9yS0{"
        $s11 = "K5JT;=BYz]"
        $s12 = ";UC>]jv?#t"
        $s13 = "$BFH hYw:."
        $s14 = "ExitProcess"
        $s15 = "SHLWAPI.dll"
        $s16 = "YQL@bSQX\\}{"
        $s17 = "COMCTL32.dll"
        $s18 = "GetProcAddress"
        $s19 = "ShellExecuteExA"
        $s20 = "CoInitialize"
condition:
    uint16(0) == 0x5a4d and filesize < 557KB and
    4 of them
}
    
