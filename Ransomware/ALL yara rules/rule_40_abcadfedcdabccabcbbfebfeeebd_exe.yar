rule abcadfedcdabccabcbbfebfeeebd_exe {
strings:
        $s1 = "runtime.assertI2I"
        $s2 = "last_insert_rowid"
        $s3 = "syscall.Ftruncate"
        $s4 = "runtime.runqsteal"
        $s5 = "io/fs.errNotExist"
        $s6 = "rename columns of"
        $s7 = "net.SplitHostPort"
        $s8 = "net/url.getScheme"
        $s9 = "reflect.StructTag.Get"
        $s10 = "runtime.cansemacquire"
        $s11 = "type..eq.net.UnixAddr"
        $s12 = "net/textproto.NewReader"
        $s13 = "OpH+GPL+WXL+_`L+ghL+opH"
        $s14 = "onoffalseyestruextrafull"
        $s15 = "non-%s value in %s.%s"
        $s16 = "syscall.CreateProcessAsUser"
        $s17 = "net/http.http2parseDataFrame"
        $s18 = "wrong # of entries in index "
        $s19 = "runtime.getproccount"
        $s20 = "type..eq.runtime.mOS"
condition:
    uint16(0) == 0x5a4d and filesize < 5590KB and
    4 of them
}
    
