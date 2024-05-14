rule faaadddffaecabcecbcbdeeadd_exe {
strings:
        $s1 = "peer misbehaved: "
        $s2 = "invalid header '`"
        $s3 = "rename columns of"
        $s4 = "last_insert_rowid"
        $s5 = "AC RAIZ FNMT-RCM0"
        $s6 = "Bad redirection: "
        $s7 = "duplicate field `"
        $s8 = "CharEmptyLooklook"
        $s9 = "`at` split index (is "
        $s10 = "fatal runtime error: "
        $s11 = "rustls::msgs::handshake"
        $s12 = "server varied selected ciphersuite"
        $s13 = "fxf gfi_i8iNibiqi?iEiji9iBiWiYiziHiIi5ili3i=iei"
        $s14 = "onoffalseyestruextrafull"
        $s15 = "testserver: in read_request: "
        $s16 = "AlertMessagePayloadlevel"
        $s17 = "wrong # of entries in index "
        $s18 = "t$t&t(t)t*t+t,t-t.t/t0t1t9t@tCtDtFtGtKtMtQtRtWt]tbtftgthtktmtntqtrt"
        $s19 = "notification message"
        $s20 = "authorization denied"
condition:
    uint16(0) == 0x5a4d and filesize < 3103KB and
    4 of them
}
    
