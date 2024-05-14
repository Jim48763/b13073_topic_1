rule ddabfacacebaaceabdb_exe {
strings:
        $s1 = "R_Bdu['DVA]"
        $s2 = "_CorExeMain"
        $s3 = "zUT0rWY3@h."
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "GetModuleHandleA"
        $s8 = "Microsoft Corporation"
        $s9 = "BefHd%LbI/fuI"
        $s10 = "Greater Manchester1"
        $s11 = "'a}t{zJDs5"
        $s12 = "h9?!2GaR[>"
        $s13 = "tru0In)foN"
        $s14 = "Z%W)NvmyXC"
        $s15 = ",D`wY{zJqT"
        $s16 = "q';T{`7Ls["
        $s17 = "'ts}Bwm$&{"
        $s18 = "Ub8wR H')J"
        $s19 = "]NF!t.4~ar"
        $s20 = "(8Je!/)Ii7"
condition:
    uint16(0) == 0x5a4d and filesize < 972KB and
    4 of them
}
    
