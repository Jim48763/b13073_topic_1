rule abeacbdbddabcaefcbacbba_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "cross device link"
        $s3 = "german-luxembourg"
        $s4 = "english-caribbean"
        $s5 = "executable format error"
        $s6 = "result out of range"
        $s7 = "directory not empty"
        $s8 = "invalid string position"
        $s9 = "ios_base::failbit set"
        $s10 = "GetConsoleOutputCP"
        $s11 = "operation canceled"
        $s12 = "9&_6^.0C)ty"
        $s13 = "_4)Fk8@sCyd"
        $s14 = "uw7jOeb,<Q$"
        $s15 = "kgFHQSy<^XE"
        $s16 = "p|aY^VqNZJA"
        $s17 = "02V!|6AN([y"
        $s18 = ">+my#qY25i3"
        $s19 = "LC_MONETARY"
        $s20 = "P4 :5nVs'hb"
condition:
    uint16(0) == 0x5a4d and filesize < 1342KB and
    4 of them
}
    
