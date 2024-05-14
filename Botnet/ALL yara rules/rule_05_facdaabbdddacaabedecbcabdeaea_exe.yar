rule facdaabbdddacaabedecbcabdeaea_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "More information at:"
        $s3 = "RegSetValueExW"
        $s4 = "1Z3VT8![Up$"
        $s5 = "#T7M{)wF~ol"
        $s6 = "M5!X]?-.lZF"
        $s7 = "/%ti{Ll~@?]"
        $s8 = "SV,M|@+<j\""
        $s9 = "j:DHOPE=TQA"
        $s10 = "]&?S>f3wKP/"
        $s11 = "]j$c\"H6dy="
        $s12 = ":x%P+ba$n<q"
        $s13 = "^K>jWbS\"[]"
        $s14 = "VarFileInfo"
        $s15 = "PB,#M4%Sx_I"
        $s16 = "W?+ocN7#dFC"
        $s17 = "P7&0Q9(rfTJ"
        $s18 = "#AZ5^{yRNB}"
        $s19 = "!%).048;=?s"
        $s20 = "+XkMHW wA-d"
condition:
    uint16(0) == 0x5a4d and filesize < 3068KB and
    4 of them
}
    
