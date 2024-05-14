rule afeaedfadbfecaffedfafc_exe {
strings:
        $s1 = "))Tl00C]00<S223M222L333M333M++J'"
        $s2 = "AutoPropertyValue"
        $s3 = "set_MainMenuStrip"
        $s4 = "1J+3vv5dfqvHv+bBL"
        $s5 = "security_question"
        $s6 = "set_AttendenceStatusLabel"
        $s7 = "lfwOf+Of8rf+DT9z+Is"
        $s8 = "3P3zr5x36Nf+J3mf3Ov+zz3"
        $s9 = "SearchComboBox"
        $s10 = "mv8HvsvO7LDEfn"
        $s11 = "1+2f9inv+CP+m3"
        $s12 = "set_SizingGrip"
        $s13 = "RuntimeHelpers"
        $s14 = "GenderImpLabel"
        $s15 = "h$%Yy--H]333M333KKL[J"
        $s16 = "get_AddressTextBox"
        $s17 = "STAThreadAttribute"
        $s18 = "AuthenticationMode"
        $s19 = "DesignerGeneratedAttribute"
        $s20 = "T+M(4O=jN/i"
condition:
    uint16(0) == 0x5a4d and filesize < 1294KB and
    4 of them
}
    
