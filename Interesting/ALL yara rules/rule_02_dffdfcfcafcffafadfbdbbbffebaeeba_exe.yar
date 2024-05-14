rule dffdfcfcafcffafadfbdbbbffebaeeba_exe {
strings:
        $s1 = "dwCreationDisposition"
        $s2 = "EnterDebugMode"
        $s3 = "GetWindowDC"
        $s4 = "_CorExeMain"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "CreateCompatibleBitmap"
        $s8 = "i destroyed your mbr"
        $s9 = "DialogResult"
        $s10 = "GdiAlphaBlend"
        $s11 = "    </application>"
        $s12 = "i want to be loved"
        $s13 = "InvalidateRect"
        $s14 = "MessageBoxIcon"
        $s15 = "piLargeVersion"
        $s16 = "set_FormatFlags"
        $s17 = "FileFlagDeleteOnClose"
        $s18 = "BLENDFUNCTION"
        $s19 = "blendFunction"
        $s20 = "DebuggingModes"
condition:
    uint16(0) == 0x5a4d and filesize < 203KB and
    4 of them
}
    
