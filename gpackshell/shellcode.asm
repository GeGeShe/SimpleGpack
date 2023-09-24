extern g_orgOep:QWORD;

.code
JmpOrgOep PROC 
    push g_orgOep;
    ret;
JmpOrgOep ENDP
end