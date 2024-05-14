rule eaccfdeeffdaedfdbefabfbafafedd_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "VirtualAllocEx"
        $s3 = "Y1t_>0|el\""
        $s4 = "o^.Z6`\"Y<B"
        $s5 = "`pv*]JLTa(>"
        $s6 = "\"La^zd)wAo"
        $s7 = "!aIKvL@Hz:;"
        $s8 = "UJ`e~EhlY\""
        $s9 = "89i*=6Z(.cY"
        $s10 = "VarFileInfo"
        $s11 = "([t8+*:a#HL"
        $s12 = "JbYZjaUT<D+"
        $s13 = "ProductName"
        $s14 = "y[@Elu\"5Sx"
        $s15 = "'R!ybj`hD>_"
        $s16 = "FileDescription"
        $s17 = "GetModuleHandleA"
        $s18 = "ILeu~Dewy<e1K4eIy,e"
        $s19 = "(1|auK_(&Tti"
        $s20 = "aYq(e\"Q-edo"
condition:
    uint16(0) == 0x5a4d and filesize < 1876KB and
    4 of them
}
    
