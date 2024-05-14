rule bcefabfcddeeafedecf_com {
strings:

condition:
    uint16(0) == 0x5a4d and filesize < 5KB and
    all of them
}
    
