rule ccebacdbfafdcccbfbdcbefd_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "%-24s %-15s 0x%x(%d) "
        $s3 = "0n^_TIXE1>0nX_XEETC\\1"
        $s4 = "dps}tntirtaex~"
        $s5 = "RegSetValueExA"
        $s6 = "3~AT_eYCTPU11P2eYCTPU"
        $s7 = "\\XB\\PERY1D_Z_^F_"
        $s8 = "1w^C\\PE|TBBPVTp11"
        $s9 = "3FBACX_EWp1"
        $s10 = "ProductName"
        $s11 = "VarFileInfo"
        $s12 = "FileDescription"
        $s13 = "GetFileSecurityA"
        $s14 = "3cTBD\\TeYCTPU11"
        $s15 = "GetModuleHandleA"
        $s16 = "<;11ctvn|d}exnbk1111"
        $s17 = "pgEHATnX_W^qq111111111AK0!11117M0!"
        $s18 = "CreateService(Parameters)"
        $s19 = "Microsoft Corporation"
        $s20 = "REG_MULTI_SZ"
condition:
    uint16(0) == 0x5a4d and filesize < 189KB and
    4 of them
}
    
