rule dabcdffbabccebebbeddfbeaaec_ps {
strings:
        $s1 = "#put evil dll in temp"
        $s2 = "namespace XPS"
        $s3 = "#put phonebook"
        $s4 = "#process cmd"
        $s5 = "#run exp "
        $s6 = "sleep(3)"
        $s7 = "finally"
        $s8 = "#clean"
condition:
    uint16(0) == 0x5a4d and filesize < 31KB and
    4 of them
}
    
