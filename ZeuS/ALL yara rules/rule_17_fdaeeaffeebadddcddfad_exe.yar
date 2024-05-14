rule fdaeeaffeebadddcddfad_exe {
strings:
        $s1 = "NfEwtJlA+]W"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "FileDescription"
        $s5 = "           </requestedPrivileges>"
        $s6 = "_rvoke<Arrays"
        $s7 = "VirtualProtect"
        $s8 = "CxxLongjEUnwxd"
        $s9 = "FkCDZ^uE*`"
        $s10 = "Copyright "
        $s11 = "1m5Z+Mr|z6"
        $s12 = "JWP(p+n_[k"
        $s13 = "I@]jkc4qHz"
        $s14 = "km0Q[i,DrB"
        $s15 = "BtAJ'n5T85("
        $s16 = "hmkAh\"0}ED"
        $s17 = "</assembly>"
        $s18 = "VP[\"hwO.Lh"
        $s19 = "Banjo Sting"
        $s20 = "ExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 199KB and
    4 of them
}
    
