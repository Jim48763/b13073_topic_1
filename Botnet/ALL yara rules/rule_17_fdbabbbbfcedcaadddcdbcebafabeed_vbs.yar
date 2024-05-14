rule fdbabbbbfcedcaadddcdbcebafabeed_vbs {
strings:
        $s1 = "End If"
condition:
    uint16(0) == 0x5a4d and filesize < 22KB and
    8 of them
}
    
