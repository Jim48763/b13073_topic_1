rule eafbabaceafafcfcedddbdbb_exe {
strings:
        $s1 = "Unfinished method"
        $s2 = "ll never be of any use."
        $s3 = "be a little less naive: don"
        $s4 = "CreateBrightnessFilter"
        $s5 = "t believe it!) that on earth there are no men"
        $s6 = "CreateSwapColorFilter"
        $s7 = "__vbaLateMemCallLd"
        $s8 = "'!d@v ~=Db("
        $s9 = "dnA4%LjHcKw"
        $s10 = "New_Caption"
        $s11 = "r5$+8\"[.uZ"
        $s12 = "ProductName"
        $s13 = "E5 dVh{\"HU"
        $s14 = "C@j-./^Lc=,"
        $s15 = "iQ\"1/l%P$g"
        $s16 = "WindowStyle"
        $s17 = "VarFileInfo"
        $s18 = "Keep quiet. Don"
        $s19 = "SetVolumeLabelA"
        $s20 = "clsFileAnalyzer"
condition:
    uint16(0) == 0x5a4d and filesize < 1243KB and
    4 of them
}
    
