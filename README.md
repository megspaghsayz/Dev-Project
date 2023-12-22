Disclaimer! The code provided in this repository is meant for educational purposes only, and is not to be used on any system without the owner's authorisation.

Warning! The C2 Client communications program contains an encryption function which is carried out recursively, starting from the folder path specified when the command is delivered and should be used only with great care. In reality this encryption function is meant to simulate a ransomware, encryption function, and should only be tested in a test environment (preferably virtualised).

My great thanks and appreciation to reenz0h at Sektor7 for his amazing Red Team Operator courses that have inspired and informed so much of this develoment project.
For any aspiring red, blue or purple teamers like myself who wish to deepen their knowledge and understanding of Windows malware functionality, I can recommend no better place to start than the 
"Malware Development Essentials Course" provided by Sektor7 for a very affordable price.

Remote Process Injector Methodology (found in "processInjector"):
Uses NTDLL API calls only for process injection functionality. 
The text section of the NTDLL DLL is copied from the on-disk DLL to overwrite and remove the AV/EDR hooks from the API functions used for process injection, before these API functions are called.
The shellcode for the C2 client program(s) that is injected into the remote process(es) is produced using the “Reflective DLL to Shellcode” methodology achieved with the python scripts found in "DLLs_to_Shellcode".

Command and Control Methodology:

The C2 server program (found in "C2_Server) is a Python flask HTTP/S server, which can be hosted on an Azure, Ubuntu Server VM, (or another server as needed) which listens for incoming HTTPS GET and POST requests from the C2 client program running on the target machine to perform command communication to the client program, receive command output from the client program, perform file upload and download to and from the target machine, and receive AES decryption keys in the event the “ransomware”, encryption command is issued.

The C2 client program (found in "C2_Client_DLLs_code"), written in C/C++, is split into two programs that operate together, a communications program and an execution program. They contain the following functionality:

Communications program: This is injected into the OneDrive process, as it uses HTTPS based communications by default for updates and file synchronisation. The communications program uses GET and POST requests to receive commands for execution from the server, send command output back, and to perform file upload and download to and from the server. Commands received from the server are written to an arbitrarily named “Input”, text file on the target machine.

Execution program: This is injected into the File Explorer process, from where it spawns a new CMD process in the background. The execution program reads commands from the “Input” file, sends them to CMD for execution, and writes the returned output to another arbitrarily named “Output”, text file.
Finally, the communication program reads command output from the “Output” file and POSTs this back to the C2 server.

Malware Obfuscation (found in "malwareObfuscation):
The C2 client program is delivered in shellcode format via the Process Injector program described above, which is a Portable Executable file. This PE file is packaged within a Microsoft Installer file (MSI), which contains the malware along with a legitimate installer program such as for a browser. The text file provided contains the example configuration file used by the WixToolset MSI creator to combine a Firefox Browser PE installer with the Remote Process Injector PE.

Finally, in the "funWithShellcode" folder can be found the file "Writing Optimized Windows Shellcode in C.html" which contains a step by step guide in how to write an executable program in C, which will be converted to PIC (Position Independent Code). Much credit and admiration to Matt Graeber (mattifestation) for this incredible explanation. For anyone familiar with the functionality of position independent code when written in assembly this will not be conceptually novel, but the fact of writing the code in C aims to simplify the process considerably. It is necessary to replace all actions performed by reference to the C standard library with a Windows API and then dynamically resolve each API used in the code from a hash value. I have successfully implemented this process with a simple message box pop-up shellcode, but have run into a bug when converting the C2 Client command execution program directly to position independent code. The issue seems to be a failure to correctly locate and utilise the "HeapAlloc" API within the "readFile" function of the program. Anyone capable of determining the cause of this issue and implementing a fix will be my hero!
