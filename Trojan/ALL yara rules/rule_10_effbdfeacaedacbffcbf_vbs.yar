rule effbdfeacaedacbffcbf_vbs {
strings:
        $s1 = "    If (char <> \" \") Then"
        $s2 = "Execute(\"vSg = \"\"\"\"\")"
        $s3 = "End Function "
        $s4 = "eQACeDnGd"
        $s5 = "EOGtnj()"
        $s6 = "    End If"
        $s7 = "XqTs = F"
        $s8 = "End Sub"
        $s9 = "End if"
        $s10 = "Next "
condition:
    uint16(0) == 0x5a4d and filesize < 7KB and
    4 of them
}
    
