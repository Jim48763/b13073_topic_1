rule dcaedadcfaaafbcacfafdaecd_exe {
strings:
        $s1 = "RemotingException"
        $s2 = "set_SigningMethod"
        $s3 = "DescriptionAttribute"
        $s4 = "TimestampGenerator"
        $s5 = "System.Linq"
        $s6 = "_CorExeMain"
        $s7 = "ComputeHash"
        $s8 = "SimpleOAuth"
        $s9 = "|prSo5Rwxue"
        $s10 = "DefaultMemberAttribute"
        $s11 = "_instancedGenerators"
        $s12 = "ISignatureGenerator"
        $s13 = "oauth_token_secret"
        $s14 = "IAsyncResult"
        $s15 = "UTF8Encoding"
        $s16 = "\\L/ CSb^.nc"
        $s17 = "NumberStyles"
        $s18 = "AppendFormat"
        $s19 = "DigiCert1%0#"
        $s20 = "AttributeExtensions"
condition:
    uint16(0) == 0x5a4d and filesize < 919KB and
    4 of them
}
    
