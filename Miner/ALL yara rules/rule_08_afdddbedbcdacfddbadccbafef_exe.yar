rule afdddbedbcdacfddbadccbafef_exe {
strings:
        $s1 = "ResolveTypeHandle"
        $s2 = "RuntimeHelpers"
        $s3 = "RuntimeFieldHandle"
        $s4 = "STAThreadAttribute"
        $s5 = ")[Y:nS-NCz2"
        $s6 = "7Pn0ld?@Xc2"
        $s7 = "=c1F<[bu@iA"
        $s8 = "yr4C+*QubP'"
        $s9 = "Z2+F5jfg\"%"
        $s10 = "ComputeHash"
        $s11 = ";Ql91,qobCS"
        $s12 = "op_Equality"
        $s13 = "w%=U\"zWI,a"
        $s14 = "Et)Tk\"=9j4"
        $s15 = "Ls}h#@b(8m^"
        $s16 = "VarFileInfo"
        $s17 = "Cl<+%`BL'I,"
        $s18 = "Y'x#WmJcLF{"
        $s19 = "ProductName"
        $s20 = "l>*&R9K'MUL"
condition:
    uint16(0) == 0x5a4d and filesize < 1912KB and
    4 of them
}
    
