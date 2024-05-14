rule afcddbafcdeedbbdebbf_exe {
strings:
        $s1 = "*runtime.mapextra"
        $s2 = "fmt.(*pp).fmt0x64"
        $s3 = "*syscall.LazyProc"
        $s4 = "SupportedVersions"
        $s5 = "*[]http.ConnState"
        $s6 = "runtime.printbool"
        $s7 = "*map[uint32]int32"
        $s8 = ")?/a*F,#)_+-){*7)"
        $s9 = "*syscall.ProcAttr"
        $s10 = "asn1:\"optional\""
        $s11 = "main.DownloadFile"
        $s12 = "assignEncodingAndSize"
        $s13 = "type..eq.net.UnixAddr"
        $s14 = "*http.http2frameCache"
        $s15 = "FirstMulticastAddress"
        $s16 = "OpH+GPL+WXL+_`L+ghL+opH"
        $s17 = "net/textproto.NewReader"
        $s18 = "c:/go/src/strconv/ftoa.go"
        $s19 = "processHelloRetryRequest"
        $s20 = "syscall.CreateProcessAsUser"
condition:
    uint16(0) == 0x5a4d and filesize < 4967KB and
    4 of them
}
    
