rule adaabdbabbdfbebcffeccfdecadbf_ps {
strings:
        $s1 = "fiNaLLy{}"
        $s2 = "}ElSe{"
condition:
    uint16(0) == 0x5a4d and filesize < 106KB and
    4 of them
}
    
