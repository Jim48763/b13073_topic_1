rule bbdceabadeddcfddeced_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "More information at:"
        $s3 = "RegSetValueExA"
        $s4 = "RC5tG@9<]8Z"
        $s5 = "dJU!*?RBa.["
        $s6 = "y(,WdmJ8Q'C"
        $s7 = "up')I~}Yn\""
        $s8 = "Z>KjDH]F'2Y"
        $s9 = "{^ a(go/8-6"
        $s10 = "9[l/L$XW#ne"
        $s11 = "ri|=ah/X*^N"
        $s12 = "/Vo`[?im0@I"
        $s13 = "`nKbZ/i1=\""
        $s14 = "!ivm,bPHf'z"
        $s15 = "OS<\"b:.9Q("
        $s16 = "DialogBoxParamA"
        $s17 = "IsWindowVisible"
        $s18 = "GetShortPathNameA"
        $s19 = "RemoveDirectoryA"
        $s20 = "DispatchMessageA"
condition:
    uint16(0) == 0x5a4d and filesize < 1497KB and
    4 of them
}
    
