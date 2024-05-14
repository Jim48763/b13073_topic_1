rule fcbabdfbbaebcedd_exe {
strings:
        $s1 = "DeserializeObject"
        $s2 = "EnsureFloatFormat"
        $s3 = "additionalProperties"
        $s4 = "WriteConstructorDate"
        $s5 = "validationEventHandler"
        $s6 = "JsonConverterAttribute"
        $s7 = "XmlNamespaceManager"
        $s8 = "set_DefaultSettings"
        $s9 = "FallbackDeleteIndex"
        $s10 = "FulfillFromLeftover"
        $s11 = "InternalFlagsFormat"
        $s12 = "BinderTypeName"
        $s13 = "<GetId>b__26_1"
        $s14 = "RuntimeHelpers"
        $s15 = "StringComparer"
        $s16 = "EnsureDateTime"
        $s17 = "ValidateNotDisallowed"
        $s18 = "CanReadMemberValue"
        $s19 = "_genericDictionary"
        $s20 = "System.Xml.XmlNode"
condition:
    uint16(0) == 0x5a4d and filesize < 770KB and
    4 of them
}
    
