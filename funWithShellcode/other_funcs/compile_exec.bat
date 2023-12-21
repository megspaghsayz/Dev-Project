@ECHO OFF

cl.exe exec_test_01.c /nologo /TC /Ox /MT /W0 /GS- /DNDEBUG /link /OUT:exec_test_04.exe /SUBSYSTEM:CONSOLE /MACHINE:x64


cl.exe exec_test.c /nologo /GL /W4 /O1 /Zl /FA /Os /TC /GS- /DNDEBUG /link /LTCG /ENTRY:"exec" /OPT:REF /OPT:ICF /SAFESEH:NO /OUT:exec_test_02.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 /NODEFAULTLIB





cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp exec_noCRT.cpp /link /LTCG "AdjustStack.obj" /OUT:exec.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 /NODEFAULTLIB /ENTRY:ExecutePayload


cl.exe exec_noCRT.cpp /GS- /GL /W4 /O1 /nologo /Zl /FA /Os /link /LTCG "AdjustStack.obj" /ENTRY:"Begin" /OPT:REF /SAFESEH:NO /SUBSYSTEM:CONSOLE /MAP /ORDER:@"function_link_order64.txt" /OPT:ICF /NOLOGO /NODEFAULTLIB

cl.exe exec_noCRT.cpp /GS- /GL /W4 /O1 /nologo /DNDEBUG /Zl /FA /Os /MT /link /LTCG "AdjustStack.obj" /ENTRY:"Begin" /OPT:REF /SAFESEH:NO /SUBSYSTEM:CONSOLE /MAP /ORDER:@"function_link_order64.txt" /OPT:ICF /NOLOGO


cl.exe exec_hashed.c /GS- /TC /GL /W4 /O1 /nologo /Zl /FA /Os /link /LTCG "AdjustStack.obj" /ENTRY:"Begin" /OPT:REF /SAFESEH:NO /SUBSYSTEM:CONSOLE /MAP /ORDER:@"function_link_order64.txt" /OPT:ICF /NOLOGO /NODEFAULTLIB


del *.obj