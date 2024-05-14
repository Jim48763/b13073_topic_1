rule ecdcadaeeaedcfabeeedcdfbb_exe {
strings:
        $s1 = "CancelButtonClick"
        $s2 = "msctls_progress32"
        $s3 = "`vector destructor iterator'"
        $s4 = "LicenseAcceptedRadio"
        $s5 = " ei muokata, vain vastaavat ikonit uusitaan."
        $s6 = "ban van!9Alkalmaznia kell az "
        $s7 = "Runtime Error!"
        $s8 = "invalid string position"
        $s9 = "Laajennettu videorender"
        $s10 = "SetConsoleCtrlHandler"
        $s11 = "GetConsoleOutputCP"
        $s12 = "vignette obsidian "
        $s13 = "cut acest logo, contacteaz"
        $s14 = "npbstNormal"
        $s15 = "Working set"
        $s16 = "glPopMatrix"
        $s17 = "`local vftable'"
        $s18 = "TRichEditViewer"
        $s19 = "%1 = Procesos PID"
        $s20 = "SetDIBitsToDevice"
condition:
    uint16(0) == 0x5a4d and filesize < 352KB and
    4 of them
}
    
