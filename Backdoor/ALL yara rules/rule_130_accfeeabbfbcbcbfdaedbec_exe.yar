rule accfeeabbfbcbcbfdaedbec_exe {
strings:
        $s1 = "FlagsAttribute"
        $s2 = "System.Linq"
        $s3 = "_CorExeMain"
        $s4 = "MsgBoxStyle"
        $s5 = "Greater Manchester1"
        $s6 = "get_EntryPoint"
        $s7 = "Jersey City1"
        $s8 = "MethodInfo"
        $s9 = "Enumerable"
        $s10 = "MethodBase"
        $s11 = "mscoree.dll"
        $s12 = "380118235959Z0}1"
        $s13 = "New Jersey1"
        $s14 = "Dbcdccaaadbbafcc1&0$"
        $s15 = "Afaedacabceacddbcace.exe"
        $s16 = "Bebeadfbdaffebbebaeebdbdbdbfe1&0$"
        $s17 = "20201209215745Z"
        $s18 = "New York1"
        $s19 = "v4.0.30319"
        $s20 = "Abdbdfbcfbeabffdfdbdbfeeabdbf1"
condition:
    uint16(0) == 0x5a4d and filesize < 3521KB and
    4 of them
}
    
