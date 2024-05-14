rule ebbeeadbeedbfdffdfbd_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "ityD-biptorCKtl"
        $s4 = "FileDescription"
        $s5 = "Microsoft Corporation"
        $s6 = "PrivateBuild"
        $s7 = "YZ[2$C2\\]^P2$C_P"
        $s8 = "VirtualProtect"
        $s9 = "h,-.$)<-hyfzf{h"
        $s10 = "LegalTrademarks"
        $s11 = "l~<SAU}bZL"
        $s12 = "Pm.32Nextd"
        $s13 = "h%',-fEEBlC"
        $s14 = "ExitProcess"
        $s15 = "SHLWAPI.dll"
        $s16 = "SpecialBuild"
        $s17 = "ADVAPI32.dll"
        $s18 = "NetApiBufferFree"
        $s19 = "GetProcAddress"
        $s20 = "OriginalFilename"
condition:
    uint16(0) == 0x5a4d and filesize < 88KB and
    4 of them
}
    
