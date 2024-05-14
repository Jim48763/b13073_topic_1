rule dccfdfafdcccadfadedbabbddefbf_exe {
strings:
        $s1 = "503121E394D83E12E210A5FB"
        $s2 = "81CE52977E1154CE7E1ED1E43906B"
        $s3 = "Tip of the Day"
        $s4 = "09D06F7E95C609F554D709377880057E95C6EEB"
        $s5 = "pIwnByU\"[L"
        $s6 = "o'BdZ0<Uku6"
        $s7 = "HotTracking"
        $s8 = "+4iod(^=9`u"
        $s9 = "1|k@yBRm4Ho"
        $s10 = "MSComctlLib"
        $s11 = "ProductName"
        $s12 = "Ur1Of|e9L_4"
        $s13 = "Rs4_o<ByUr1"
        $s14 = "RC4;K[q+Ur1"
        $s15 = ":5mo4(w=9L;"
        $s16 = "Tc+3QmodB8 "
        $s17 = "gr1:Xey_fC4"
        $s18 = "}1RBQq.>K0b"
        $s19 = "_N>IodByUr1"
        $s20 = "VarFileInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 227KB and
    4 of them
}
    
