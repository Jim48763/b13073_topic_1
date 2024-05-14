rule bfdfdffcbccdfbbddeacaacffbdfad_ps {
strings:
        $s1 = "function lC {"
        $s2 = "Param ("
condition:
    uint16(0) == 0x5a4d and filesize < 10KB and
    4 of them
}
    
