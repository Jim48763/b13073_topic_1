rule efaeaffdbfddddacebccadfdd_dll {
strings:
        $s1 = "SreismeoW"
        $s2 = "!8+8;8N8Z8p8y8~8"
        $s3 = "dll32dllTr.dll"
        $s4 = ".reloc"
        $s5 = "8 :-:y:"
        $s6 = "@.data"
        $s7 = "Richq"
        $s8 = "44V4W7"
        $s9 = ".text"
condition:
    uint16(0) == 0x5a4d and filesize < 442KB and
    4 of them
}
    
