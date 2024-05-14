rule dcfeccaaeeeedefbebaefcaae_com {
strings:
        $s1 = " /\\/\\/    "
        $s2 = "!< u#"
condition:
    uint16(0) == 0x5a4d and filesize < 5KB and
    all of them
}
    
