rule ecfcffadcedecbbbeaaeffbdd_dll {
strings:
        $s1 = ":TSslCertTools.:5"
        $s2 = "id-cmc-dataReturn"
        $s3 = "Trailer Field: 0x"
        $s4 = "encrypted track 2"
        $s5 = "TRttiClassRefType"
        $s6 = "\\Program Files\\"
        $s7 = "Cipher list empty"
        $s8 = "FTP Commander Pro"
        $s9 = "EndFunctionInvoke"
        $s10 = "TRttiManagedField"
        $s11 = "last_insert_rowid"
        $s12 = "TCollateXCompare@"
        $s13 = "OBJECT DESCRIPTOR"
        $s14 = "policyConstraints"
        $s15 = "ToShortUTF8String"
        $s16 = "MenuItemFromPoint"
        $s17 = "StaticSynchronize"
        $s18 = "TLzmaCompressProgress"
        $s19 = "CoAddRefServerProcess"
        $s20 = "httpoBandwidthControl"
condition:
    uint16(0) == 0x5a4d and filesize < 15134KB and
    4 of them
}
    
