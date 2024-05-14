rule eeeabbaafeacdaeacecefddfbcef_dll {
strings:
        $s1 = "cabac decode of qscale diff failed at %d %d"
        $s2 = "Unknown function in '%s'"
        $s3 = "707172737475767778797:7;7<7=7>7?7@7A7B7C7D7E7F7G7H7I7J7K7L7M7N7O74;5;6;7;"
        $s4 = "Error! Got no format or no keyframe!"
        $s5 = "limiting QP %f -> %f"
        $s6 = "out of room to push characters"
        $s7 = "read_quant_table error"
        $s8 = "Bad value for reserved field"
        $s9 = "Missing reference picture"
        $s10 = "my guess is %d bits ;)"
        $s11 = "_Jv_RegisterClasses"
        $s12 = "missing picture in access unit"
        $s13 = "x264 - core %d"
        $s14 = "Missing GSM magic!"
        $s15 = "2Pass file invalid"
        $s16 = "NAL %d at %d/%d length %d"
        $s17 = "#%),.247:<?"
        $s18 = "&-5=>6.'/7?"
        $s19 = "=;853/-*&$ "
        $s20 = "B$%&'()KLMn"
condition:
    uint16(0) == 0x5a4d and filesize < 3537KB and
    4 of them
}
    
