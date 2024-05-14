rule acbdbbdcfbdebecbcdddadffdeacbbbf_wsf {
strings:
        $s1 = "</script>"
        $s2 = "<package>"
        $s3 = "</job>"
condition:
    uint16(0) == 0x5a4d and filesize < 122KB and
    8 of them
}
    
