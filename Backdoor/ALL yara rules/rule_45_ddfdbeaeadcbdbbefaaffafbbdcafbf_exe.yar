rule ddfdbeaeadcbdbbefaaffafbbdcafbf_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "\"7\\9wp:d@0 V"
        $s3 = "Invalid 8ro"
        $s4 = "u!+`)@ D1=*"
        $s5 = "+^JK$Bl4WpH"
        $s6 = "F8]<V.DX^Zl"
        $s7 = "RSTUVWXYQZx"
        $s8 = "ProductName"
        $s9 = "b5xNdsAn1w4"
        $s10 = "VarFileInfo"
        $s11 = "JwD\";Bji<g"
        $s12 = "h.87r@tlvwx"
        $s13 = "4DE290-(J:F"
        $s14 = "7(d$H\"CB,_"
        $s15 = "FileDescription"
        $s16 = "GetModuleHandleA"
        $s17 = "<\"=*>2?:?B?J?R?Z?b?j?r?z?"
        $s18 = "EnableWindow"
        $s19 = "[aXytr'n]g0'"
        $s20 = "xWz[|_~c~gMk"
condition:
    uint16(0) == 0x5a4d and filesize < 480KB and
    4 of them
}
    
