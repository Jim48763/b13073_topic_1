rule dcbddcbbfceffcbbaefefaeebabeafffcc_exe {
strings:
        $s1 = "VK_MEDIA_PREV_TRACK"
        $s2 = "?456789:;<="
        $s3 = "VK_LAUNCH_MAIL"
        $s4 = "\\rundll32.exe"
        $s5 = "VK_VOLUME_DOWN"
        $s6 = "VK_BROWSER_STOP"
        $s7 = "VK_NUMPAD9"
        $s8 = "VK_DECIMAL"
        $s9 = "displayName"
        $s10 = "VK_SUBTRACT"
        $s11 = "VK_MULTIPLY"
        $s12 = "M'/^G$A3uuI"
        $s13 = "VK_SNAPSHOT"
        $s14 = "VK_SEPARATOR"
        $s15 = "Advapi32.dll"
        $s16 = "SerialNumber"
        $s17 = "VK_BROWSER_REFRESH"
        $s18 = "oleaut32.dll"
        $s19 = "user32.dll"
        $s20 = "VK_MBUTTON"
condition:
    uint16(0) == 0x5a4d and filesize < 57KB and
    4 of them
}
    