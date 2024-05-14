rule edabbceeaccbceececfaebef_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "cross device link"
        $s4 = "opj_image_tile_create"
        $s5 = "`vector destructor iterator'"
        $s6 = "opj_image_data_alloc"
        $s7 = "opj_has_thread_support"
        $s8 = "Cannot allocate memory"
        $s9 = "executable format error"
        $s10 = "result out of range"
        $s11 = "directory not empty"
        $s12 = "opj_codec_set_threads"
        $s13 = "ios_base::failbit set"
        $s14 = "operation canceled"
        $s15 = "Invalid tile width"
        $s16 = "GetConsoleOutputCP"
        $s17 = "%\",0RE93GZ"
        $s18 = "LC_MONETARY"
        $s19 = "packet body"
        $s20 = " cblkh=2^%d"
condition:
    uint16(0) == 0x5a4d and filesize < 1279KB and
    4 of them
}
    
