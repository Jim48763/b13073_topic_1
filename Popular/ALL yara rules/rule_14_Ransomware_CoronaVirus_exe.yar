rule Ransomware_CoronaVirus_exe {
strings:
        $s1 = "Min: (%.2f, %.2f)"
        $s2 = "ESCAPE to revert."
        $s3 = "\"imgui\" letters"
        $s4 = "DialboxSerialPort"
        $s5 = " NavEnableGamepad"
        $s6 = "GetEnvironmentStrings"
        $s7 = "click on a button to set focus"
        $s8 = "(%6.1f,%6.1f) (%6.1f,%6.1f) Size (%6.1f,%6.1f) %s"
        $s9 = "%s: %d entries, %d bytes"
        $s10 = "Disable tree indentation"
        $s11 = "Cannot create window"
        $s12 = "I am a fancy tooltip"
        $s13 = "Hovering me sets the"
        $s14 = "input text (w/ hint)"
        $s15 = "Don't ask me next time"
        $s16 = "glutInitContextFunc"
        $s17 = "glutLeaveFullScreen"
        $s18 = "SelectableTextAlign"
        $s19 = "Text baseline:"
        $s20 = "TabBar (%d tabs)%s"
condition:
    uint16(0) == 0x5a4d and filesize < 1043KB and
    4 of them
}
    
