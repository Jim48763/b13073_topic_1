rule bfcddcecbcadaafdcddbbcac_exe {
strings:
        $s1 = "CazlingCo|ventio|"
        $s2 = "AssemplyBuilrerAcce"
        $s3 = "   .<securwty>"
        $s4 = "CreatsMember`efsDelsgates"
        $s5 = "Assembzy.Deleuates"
        $s6 = "__StoticArroyInitT"
        $s7 = "(.NEfFromew"
        $s8 = "\"G#StringY"
        $s9 = ".NETbramewo"
        $s10 = "Syste{.Xaml"
        $s11 = "IOExce~tion"
        $s12 = "op_Equality"
        $s13 = "_CorExsMain"
        $s14 = "VarFileInfo"
        $s15 = "QomV{sipleA"
        $s16 = "namicMsthod"
        $s17 = "CocheStrwng"
        $s18 = "A~plicatwon"
        $s19 = "_InnerSxcepti}n"
        $s20 = "GetTromRes}urce"
condition:
    uint16(0) == 0x5a4d and filesize < 462KB and
    4 of them
}
    
