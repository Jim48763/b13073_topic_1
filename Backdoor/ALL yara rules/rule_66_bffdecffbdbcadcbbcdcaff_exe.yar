rule bffdecffbdbcadcbbcdcaff_exe {
strings:
        $s1 = "direzioneSpecialShip"
        $s2 = "btnStart_Click"
        $s3 = "RuntimeHelpers"
        $s4 = "STAThreadAttribute"
        $s5 = "op_Equality"
        $s6 = ";~dnE5+F$r-"
        $s7 = "blackSprite"
        $s8 = "_CorExeMain"
        $s9 = "p<]:/K#ua0S"
        $s10 = "GPu|$.Sway/"
        $s11 = "1LT%Yrq>R/d"
        $s12 = "Hv.+[zI3Q\""
        $s13 = "ProductName"
        $s14 = "btnOK_Click"
        $s15 = "_07lPsi3obz"
        $s16 = "VarFileInfo"
        $s17 = "DefaultMemberAttribute"
        $s18 = "set_MinimizeBox"
        $s19 = "FileDescription"
        $s20 = "KeyEventHandler"
condition:
    uint16(0) == 0x5a4d and filesize < 724KB and
    4 of them
}
    
