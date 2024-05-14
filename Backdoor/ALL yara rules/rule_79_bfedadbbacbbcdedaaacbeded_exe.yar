rule bfedadbbacbbcdedaaacbeded_exe {
strings:
        $s1 = "@nnc^kjibueObject"
        $s2 = "MinorImageVersion"
        $s3 = "ReadOnlyCollZCdaklCase"
        $s4 = "VirtualAllocEx"
        $s5 = "StringComparer"
        $s6 = "comm^qk)`nm?0l"
        $s7 = "MajorLinkerVersion"
        $s8 = "MarshalAsAttribute"
        $s9 = "QdcurityIdentifier"
        $s10 = "HbwGilZQnjf"
        $s11 = "hAy|BmsExit"
        $s12 = "?~]DkdliFUN"
        $s13 = "X@moLj}b'^_"
        $s14 = "SizeOfIm^Gu"
        $s15 = "op_Equality"
        $s16 = "byKEclkvoet"
        $s17 = "mzhnpurFTj~"
        $s18 = "_CorExeMain"
        $s19 = "IDiLo`tbclZ"
        $s20 = "SocketFl^x|"
condition:
    uint16(0) == 0x5a4d and filesize < 254KB and
    4 of them
}
    
