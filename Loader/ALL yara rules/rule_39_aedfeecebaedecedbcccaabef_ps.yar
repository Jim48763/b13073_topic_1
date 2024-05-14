rule aedfeecebaedecedbcccaabef_ps {
strings:

condition:
    uint16(0) == 0x5a4d and filesize < 8KB and
    all of them
}
    
