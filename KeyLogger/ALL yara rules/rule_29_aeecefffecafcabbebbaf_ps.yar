rule aeecefffecafcabbebbaf_ps {
strings:

condition:
    uint16(0) == 0x5a4d and filesize < 8KB and
    4 of them
}
    
