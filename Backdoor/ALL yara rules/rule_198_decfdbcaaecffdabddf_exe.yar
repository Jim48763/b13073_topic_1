rule decfdbcaaecffdabddf_exe {
strings:
        $s1 = "u%;ABCDEFgVV"
        $s2 = "Class_TPUtilW"
        $s3 = "AR7U$u]7!L]CqL"
        $s4 = "VirtualProtect"
        $s5 = "Pht,4R1X\""
        $s6 = "_CRuntime e"
        $s7 = "& Setup\\In"
        $s8 = "ExitProcess"
        $s9 = "PACKAGEINFO"
        $s10 = "SHGetMalloc"
        $s11 = "vQ|ie|eJ~aKf"
        $s12 = "SysFreeString"
        $s13 = "GetProcAddress"
        $s14 = "oleaut32.dll"
        $s15 = "VirtualAlloc"
        $s16 = "user32.dll"
        $s17 = "are\\Micros"
        $s18 = "VirtualFree"
        $s19 = "FtpPutFileW"
        $s20 = "lstrlenWWritev"
condition:
    uint16(0) == 0x5a4d and filesize < 38KB and
    4 of them
}
    
