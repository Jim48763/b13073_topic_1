rule defeaacccbbeaeebcbfddddddaffcde_exe {
strings:
        $s1 = "picElementySciany"
        $s2 = "Verifing Test Message"
        $s3 = " intellectuelle de mworld."
        $s4 = "28C4C820-401A-101B-A3C9-08002B2F49FB"
        $s5 = "MSComctlLib"
        $s6 = "PrintModule"
        $s7 = "ProductName"
        $s8 = "intropm.wav"
        $s9 = "VarFileInfo"
        $s10 = "ntMUJpljoag"
        $s11 = "test message verified failed"
        $s12 = "mnuFreeSoftware"
        $s13 = "FileDescription"
        $s14 = "rightOutsetlong"
        $s15 = "Message Encoded:"
        $s16 = "Already Present "
        $s17 = "MotorolaScreentype"
        $s18 = "SecurityForm"
        $s19 = "picGhostMask"
        $s20 = "PaintDesktop"
condition:
    uint16(0) == 0x5a4d and filesize < 509KB and
    4 of them
}
    
