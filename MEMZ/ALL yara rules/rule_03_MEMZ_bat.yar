rule MEMZ_bat {
strings:
        $s1 = "start \"\" %v%"
        $s2 = "@echo off"
condition:
    uint16(0) == 0x5a4d and filesize < 17KB and
    4 of them
}
    
