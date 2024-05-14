rule dacfffbcbcbbfdfdfbbadfbaaf_dll {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "EVariantDispatchError"
        $s3 = "TInterfacedPersistent"
        $s4 = "ImmSetCompositionFontA"
        $s5 = "[n [ha Jn[H*d?HXa?e"
        $s6 = " 2001, 2002 Mike Lischke"
        $s7 = "VirtualAllocEx"
        $s8 = "OnMouseWheelUp"
        $s9 = "0HtZwsWa;bHHg3"
        $s10 = "GetWindowTheme"
        $s11 = "oXTw_o2CoY]vxG"
        $s12 = "EExternalException"
        $s13 = "TContextPopupEvent"
        $s14 = "{ZsW;T=R5y>"
        $s15 = "Ja9sAR*pCdo"
        $s16 = "iyIz^EbvG 2"
        $s17 = "{5*aIJrl|4E"
        $s18 = "gV/foyQUNtR"
        $s19 = "U$s-p`K#QjJ"
        $s20 = "df`y8n:]?m{"
condition:
    uint16(0) == 0x5a4d and filesize < 637KB and
    4 of them
}
    
