rule cdccecfefadbefdedb_dll {
strings:
        $s1 = "cross device link"
        $s2 = "english-caribbean"
        $s3 = "CreateThreadpoolTimer"
        $s4 = "fp_format_e_internal"
        $s5 = "executable format error"
        $s6 = "result out of range"
        $s7 = "directory not empty"
        $s8 = "<file unknown>"
        $s9 = "Runtime Error!"
        $s10 = "invalid string position"
        $s11 = "common_message_window"
        $s12 = "ios_base::failbit set"
        $s13 = "operation canceled"
        $s14 = "common_vsnprintf_s"
        $s15 = "LC_MONETARY"
        $s16 = "ProductName"
        $s17 = "x|CDY2P0\"B"
        $s18 = "jPo7>29;S-M"
        $s19 = "VarFileInfo"
        $s20 = "=FZ-wcQ2(zd"
condition:
    uint16(0) == 0x5a4d and filesize < 3365KB and
    4 of them
}
    
