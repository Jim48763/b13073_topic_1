rule bcacbcefffbbbaabedfbdbd_com {
strings:
        $s1 = "!Turbo Kukac 9.9      $"
condition:
    uint16(0) == 0x5a4d and filesize < 5KB and
    all of them
}
    
