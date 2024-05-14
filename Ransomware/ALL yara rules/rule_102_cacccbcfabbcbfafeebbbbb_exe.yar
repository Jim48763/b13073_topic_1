rule cacccbcfabbcbfafeebbbbb_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "*&\"ADQ`zpE"
        $s5 = "w`-+{pP;KNG"
        $s6 = "<$wl\" ~nOz"
        $s7 = ">98\"SZB70J"
        $s8 = "[<ymGTSJdn)"
        $s9 = "b,M:<Al~ki+"
        $s10 = "4J*z$jV'<%6"
        $s11 = "sY@bn7N}y2A"
        $s12 = "VarFileInfo"
        $s13 = "ProductName"
        $s14 = "HVz8Ughds\""
        $s15 = "jW4Hq#|L*]7"
        $s16 = "8s4W<%cS:fA"
        $s17 = "Aerwo1=k !l"
        $s18 = "8)$}^LRo.|`"
        $s19 = "FileDescription"
        $s20 = "IsWindowVisible"
condition:
    uint16(0) == 0x5a4d and filesize < 3859KB and
    4 of them
}
    
