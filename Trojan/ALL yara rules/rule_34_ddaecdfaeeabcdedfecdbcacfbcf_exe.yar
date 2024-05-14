rule ddaecdfaeeabcdedfecdbcacfbcf_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "Obsoleting.exe"
        $s3 = "RelativeSource"
        $s4 = "InternalPartitionEnumerator"
        $s5 = "tubiaoshangshengqushi"
        $s6 = "RuntimeFieldHandle"
        $s7 = "STAThreadAttribute"
        $s8 = "ProductName"
        $s9 = "_CorExeMain"
        $s10 = "VarFileInfo"
        $s11 = "Prestamping"
        $s12 = "FileDescription"
        $s13 = "StrokeDashArray"
        $s14 = "GetPropertyValue"
        $s15 = "435435[G32e43432t4]325[54P5r4]43554o35c435[43A54d6]443543354355d54[7r65]7e5s8[7s558]"
        $s16 = "./Fonts/#iconfont)"
        $s17 = "AncestorType"
        $s18 = "Synchronized"
        $s19 = "CornerRadius"
        $s20 = "ColumnDefinitions"
condition:
    uint16(0) == 0x5a4d and filesize < 82KB and
    4 of them
}
    
