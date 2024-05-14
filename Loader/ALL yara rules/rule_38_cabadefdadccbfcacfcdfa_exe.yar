rule cabadefdadccbfcacfcdfa_exe {
strings:
        $s1 = "obagoFsouth-korea"
        $s2 = "t,4h#8ldT/_"
        $s3 = "Y`jt7@3V0;k"
        $s4 = "^_aCTi\"wH*"
        $s5 = " !\"#$%&'()"
        $s6 = "qx*piZ %`J,"
        $s7 = "VarFileInfo"
        $s8 = "AFX_DIALOG_LAYOUT"
        $s9 = "pq=MqeSuAYT&"
        $s10 = "s Hierarchyn"
        $s11 = "JkgV`\">a\"rb"
        $s12 = "public:Opro[l"
        $s13 = "#S_mf+X-_}n_."
        $s14 = "VirtualProtect"
        $s15 = "Unknown excep5"
        $s16 = "0j@(8%ob$;"
        $s17 = " Descrilo="
        $s18 = "tM<it-<ot)<ut%<x5k"
        $s19 = "Vo \"se yup"
        $s20 = ":>\"4D4~Zl,"
condition:
    uint16(0) == 0x5a4d and filesize < 507KB and
    4 of them
}
    
