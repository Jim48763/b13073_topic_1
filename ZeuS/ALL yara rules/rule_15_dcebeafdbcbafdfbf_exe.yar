rule dcebeafdbcbafdfbf_exe {
strings:
        $s1 = "[|lbxllz*Ckglfhnx"
        $s2 = "GetBestInterfaceEx"
        $s3 = "ProductName"
        $s4 = " ]Q3uqKH7@x"
        $s5 = "VarFileInfo"
        $s6 = "B8:dTEDOVH_"
        $s7 = "QVWTUZ[X@y~"
        $s8 = "9*-ftu|+ms&"
        $s9 = "7Vsywyytv>G|xtm"
        $s10 = "FileDescription"
        $s11 = "gLTKPMLO GLV`N`"
        $s12 = "TerminateProcess"
        $s13 = "=r{+:=(.:&(~ 7':"
        $s14 = "WriteProcessMemory"
        $s15 = "Pvbz`zdtWkyp"
        $s16 = "aCAJGgLVqC0u"
        $s17 = "RegEnumKeyExW"
        $s18 = "QAuHU-& pGQGV"
        $s19 = "MakeSelfRelativeSD"
        $s20 = "xkl7ytutwypp`9"
condition:
    uint16(0) == 0x5a4d and filesize < 8312KB and
    4 of them
}
    
