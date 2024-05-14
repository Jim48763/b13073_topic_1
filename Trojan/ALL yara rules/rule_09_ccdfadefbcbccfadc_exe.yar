rule ccdfadefbcbccfadc_exe {
strings:
        $s1 = "-:T#?:V!?:C&<:F&=:E'=:"
        $s2 = "y#3:u6::r7::p78:~\"2:X"
        $s3 = ":S'4:g-0:h.0:r(=:z5=:"
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "GetWindowDC"
        $s7 = "_T.aVmd8k*;"
        $s8 = "shellexecute=kabe.bat"
        $s9 = "MS Sans Serif\""
        $s10 = "__vbaVarLateMemSt"
        $s11 = "CreateCompatibleBitmap"
        $s12 = "GetSystemPaletteEntries"
        $s13 = "kJ)4hl[pB\\I"
        $s14 = "TdUI^Ou||{q-"
        $s15 = "FolderExists"
        $s16 = "__vbaLenBstr"
        $s17 = "USEAUTOPLAY=1"
        $s18 = "wscript.shell"
        $s19 = "__vbaErrorOverflow"
        $s20 = " :L4::AZ`:`]Q:x{{:3+.:"
condition:
    uint16(0) == 0x5a4d and filesize < 337KB and
    4 of them
}
    
