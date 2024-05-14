rule fbccabaeafebbbabaccaab_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "pi6R/a2$.je"
        $s3 = "z>0mU\"|^y]"
        $s4 = "a-q1le9d>yi"
        $s5 = "ko@GI=Fy6~r"
        $s6 = ":*~JN}p^h?E"
        $s7 = "3AC! O{g}Z."
        $s8 = "YR~?^<%>#2|"
        $s9 = "q\"_A/S8}TH"
        $s10 = "ProductName"
        $s11 = "_@~f;)nT.oG"
        $s12 = "VarFileInfo"
        $s13 = "*2$x;}Squ(a"
        $s14 = "TQ-DlC 7mw4"
        $s15 = "g:]JR^lHz/c"
        $s16 = "FileDescription"
        $s17 = "GetModuleHandleA"
        $s18 = "GetCurrentDirectoryA"
        $s19 = "CreateCompatibleDC"
        $s20 = "RT4UKM&k\\Vt"
condition:
    uint16(0) == 0x5a4d and filesize < 1595KB and
    4 of them
}
    
