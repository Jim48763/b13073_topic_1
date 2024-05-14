rule fbdefdeafdbdecefecfddbdd_exe {
strings:
        $s1 = "*runtime.mapextra"
        $s2 = "fmt.(*pp).fmt0x64"
        $s3 = "*syscall.LazyProc"
        $s4 = "SupportedVersions"
        $s5 = "*[]http.ConnState"
        $s6 = "*big.RoundingMode"
        $s7 = "runtime.printbool"
        $s8 = "*map[uint32]int32"
        $s9 = "asn1:\"optional\""
        $s10 = "*oss.ClientOption"
        $s11 = "net/url.getscheme"
        $s12 = "assignEncodingAndSize"
        $s13 = "type..eq.net.UnixAddr"
        $s14 = "*http.http2frameCache"
        $s15 = "FirstMulticastAddress"
        $s16 = "OpH+GPL+WXL+_`L+ghL+opH"
        $s17 = "net/textproto.NewReader"
        $s18 = "type..eq.runtime._defer"
        $s19 = "type..hash.os.ProcessState"
        $s20 = "syscall.CreateProcessAsUser"
condition:
    uint16(0) == 0x5a4d and filesize < 6040KB and
    4 of them
}
    
