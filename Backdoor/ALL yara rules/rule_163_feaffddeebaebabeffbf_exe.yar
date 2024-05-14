rule feaffddeebaebabeffbf_exe {
strings:
        $s1 = "File Download Failed!"
        $s2 = "/minimum/version.zip"
        $s3 = "RegSetValueExA"
        $s4 = "28C4C820-401A-101B-A3C9-08002B2F49FB"
        $s5 = "http://ocsp.comodoca.com0"
        $s6 = "UzpVersion2"
        $s7 = "modRegistry"
        $s8 = "MSComctlLib"
        $s9 = "/others.zip"
        $s10 = "VarFileInfo"
        $s11 = "HModCPUINFO"
        $s12 = "K.D.K. Software"
        $s13 = "DeviceIoControl"
        $s14 = "rightOutsetlong"
        $s15 = "0.0KB (0 bytes)"
        $s16 = "Uses a local area network "
        $s17 = "Down Load Manager"
        $s18 = "Hidden sectors = "
        $s19 = "BytesPerSector = "
        $s20 = "<KDKUpdateUtility"
condition:
    uint16(0) == 0x5a4d and filesize < 559KB and
    4 of them
}
    
