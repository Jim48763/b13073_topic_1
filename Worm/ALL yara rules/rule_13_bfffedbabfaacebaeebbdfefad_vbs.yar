rule bfffedbabfaacebaeebbdfefad_vbs {
strings:

condition:
    uint16(0) == 0x5a4d and filesize < 92KB and
    4 of them
}
    
