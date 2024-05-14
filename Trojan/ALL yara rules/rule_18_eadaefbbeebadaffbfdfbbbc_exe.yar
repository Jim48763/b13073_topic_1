rule eadaefbbeebadaffbfdfbbbc_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = ">b:rWm89K.F"
        $s3 = "`\"h8j.t$;E"
        $s4 = ";k9h*x\"r!p"
        $s5 = "s`?~m|wr[Db"
        $s6 = "ProductName"
        $s7 = "oa~{hu4sbq."
        $s8 = "_CorExeMain"
        $s9 = "V{pefgzmu]h"
        $s10 = "}zwdq0o~mJ'"
        $s11 = "9`0,w~'n>6a"
        $s12 = ">f6n8#i1a5_"
        $s13 = "ImYQdKrvVt?"
        $s14 = "VarFileInfo"
        $s15 = "T{2ins(}dkB"
        $s16 = "FileDescription"
        $s17 = "fefabadd.Resources.resources"
        $s18 = "Synchronized"
        $s19 = "FpZD`|vpEKay"
        $s20 = "X{tzB-f;d\\4"
condition:
    uint16(0) == 0x5a4d and filesize < 672KB and
    4 of them
}
    
