rule dabcbecbecbfbdfcbcebeeecf_exe {
strings:
        $s1 = "1J+3vv5dfqvHv+bBL"
        $s2 = "Customer Name not entered"
        $s3 = "lfwOf+Of8rf+DT9z+Is"
        $s4 = "3P3zr5x36Nf+J3mf3Ov+zz3"
        $s5 = "mv8HvsvO7LDEfn"
        $s6 = "1+2f9inv+CP+m3"
        $s7 = "RuntimeHelpers"
        $s8 = "System.Data.Common"
        $s9 = "STAThreadAttribute"
        $s10 = "AuthenticationMode"
        $s11 = "DesignerGeneratedAttribute"
        $s12 = "0Pmv8Rz3+bn"
        $s13 = "f73+DjKcYai"
        $s14 = "MsgBoxStyle"
        $s15 = "ProductName"
        $s16 = "jX2Pr1nv3af"
        $s17 = "Customer ID"
        $s18 = "jetp9q1f8Xv"
        $s19 = "yzi0B8jPfNr"
        $s20 = "8zts+S5Oyvq"
condition:
    uint16(0) == 0x5a4d and filesize < 838KB and
    4 of them
}
    
