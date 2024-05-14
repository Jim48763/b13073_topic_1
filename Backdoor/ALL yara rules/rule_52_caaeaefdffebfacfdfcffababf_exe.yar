rule caaeaefdffebfacfdfcffababf_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "_CorExeMain"
        $s3 = "MsgBoxStyle"
        $s4 = "MsgBoxResult"
        $s5 = "NewLateBinding"
        $s6 = "Greater Manchester1"
        $s7 = "GetObjectValue"
        $s8 = "Jersey City1"
        $s9 = "Debacfababdceba1&0$"
        $s10 = "mscoree.dll"
        $s11 = "380118235959Z0}1"
        $s12 = "New Jersey1"
        $s13 = "201217081256Z"
        $s14 = "{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}{11}{12}{13}{14}{15}{16}{17}{18}{19}{20}{21}"
        $s15 = "Bcdefbeafacdcbbccabeecbadfade1"
        $s16 = "GetDomain"
        $s17 = "New York1"
        $s18 = "{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}{11}{12}{13}{14}"
        $s19 = "v4.0.30319"
        $s20 = "{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}"
condition:
    uint16(0) == 0x5a4d and filesize < 4234KB and
    4 of them
}
    
