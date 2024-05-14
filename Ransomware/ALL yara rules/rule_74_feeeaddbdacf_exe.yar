rule feeeaddbdacf_exe {
strings:
        $s1 = "vzgvg=3F~3`zp{vaif`gv"
        $s2 = "gv}3dza3vz}urp{3}fa3q"
        $s3 = "333333u|}g>dvzt{g)3%##("
        $s4 = "33333333/{!-3F}`vav3U|awvaf}tv}3/<{!-"
        $s5 = "v}3Z}u|a~rgz|}v}3qvt"
        $s6 = "CreateIoCompletionPort"
        $s7 = "3333333333~ratz}>q|gg|~)3>\"ck("
        $s8 = "/wze3zw.4gvkg4-/<wze-"
        $s9 = "9#9M:S:M;S;.<4<3?M?|?"
        $s10 = "GetConsoleOutputCP"
        $s11 = "{ggc)<<~v~vqzr=g|c"
        $s12 = "ProductName"
        $s13 = "z}t)3g|fp{("
        $s14 = "VarFileInfo"
        $s15 = "FileDescription"
        $s16 = "InternetCrackUrlA"
        $s17 = "}g|3gzv~c|3`v3avbfzvav3crar3avpfcvara3"
        $s18 = "GetModuleHandleA"
        $s19 = "3g|w|`3`f`3wrg|`3j3rap{ze|`=3"
        $s20 = "        uiAccess=\"false\" />"
condition:
    uint16(0) == 0x5a4d and filesize < 430KB and
    4 of them
}
    
