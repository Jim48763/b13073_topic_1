rule cdbedcdfdefeddfe_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "__vbaVerifyVarObj"
        $s3 = "LoadAcceleratorsW"
        $s4 = "CreateThreadpoolTimer"
        $s5 = "_o__register_onexit_function"
        $s6 = "NtQueryWnfStateData"
        $s7 = "RegSetValueExW"
        $s8 = "originCallerModule"
        $s9 = "|Ct*dBvcN\""
        $s10 = "Hl]J)u?STEq"
        $s11 = "qNgum9J_&GD"
        $s12 = "MSComctlLib"
        $s13 = "LoadStringW"
        $s14 = "J-+!D63^E42"
        $s15 = "Q\"VP&$<lC:"
        $s16 = "ProductName"
        $s17 = "aK63Lqpm:H|"
        $s18 = "L&\"kM%#DR "
        $s19 = "PrintDlgExW"
        $s20 = "FreshWindow"
condition:
    uint16(0) == 0x5a4d and filesize < 1564KB and
    4 of them
}
    
