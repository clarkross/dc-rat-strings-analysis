# DCRat Static Strings Analysis

MalwareBazaar entry

SHA256 Hash:
```ac15d82441447b30e13ba57c3c2ab12dae50e7396c74991393bd225f3784aab9```

**Resources**
* Malware Bazaar page for the malware -- (not included in repo)
	* https://bazaar.abuse.ch/sample/ac15d82441447b30e13ba57c3c2ab12dae50e7396c74991393bd225f3784aab9/
* REMnux
	https://remnuxnux.org/
* Documentation for static properties analysis tools in REMnux
	* https://docs.remnux.org/discover-the-tools/examine+static+properties/general

# Unpacking Archive

1. Creating directory to store static analysis information.

```bash
mkdir sample_master static_analysis # store archive samples and create an analysis folder for storing resulting information.
```

2. Extracting malware archive and defanging.

```bash
7z e ~/sample_master/ac15d82441447b30e13ba57c3c2ab12dae50e7396c74991393bd225f3784aab9.zip

mkdir ~/static_analysis/dcrat_23MAR2024 # giving the sample a dedicated directory to more easily keep track of all the information gathered.

mv ac15d82441447b30e13ba57c3c2ab12dae50e7396c74991393bd225f3784aab9.exe ~/static_analysis/dcrat_23MAR2024/dcrat_23MAR2024exe.sample # defang exe file extension
```

# Initial Observation

* Running file command

```bash
remnux@remnux:~/static_analysis/dcrat_23MAR2024$ file dcrat_23MAR2024exe.sample 
dcrat_23MAR2024exe.sample: PE32 executable (GUI) Intel 80386, for MS Windows

# Results Portable Executable
```

* Running ```strings``` & outputting to .txt: 

```bash
strings dcrat_23MAR2024exe.sample > dcrat_23MAR2024exe.strings.txt

code dcrat_23MAR2024exe.strings.txt # opening in vscode for a bit of cleanup and observation.
```

* I tossed a few keywords into a bash script to run against the strings output to see if we can quickly gather any intel hints.

```bash
#!/bin/bash
dir=$1

cat "$dir" | grep -ie "keylogger" -e "host" -e "port" -e "http" -e "victim" -e "isconnected" -e "registry" -e "send" -e "connect" -e "receive" -e "get_" -e ".exe" -e ".com" -e "delete" -e "password" -e "ransom" -e "encryption" -e "crypt"

exit
```

```bash
remnux@remnux:~/static_analysis/dcrat_23MAR2024$ sudo chmod +x keywords.sh
remnux@remnux:~/static_analysis/dcrat_23MAR2024$ ./keywords.sh ./dcrat_23MAR2024exe.strings.txt > dcrat_23MAR2024exe.strings.keywords # outputted the keywords to a .txt
remnux@remnux:~/static_analysis/dcrat_23MAR2024$ code dcrat_23MAR2024exe.keywords.txt  # using vscode to take a gander.
```

**Lines To Note**

```
-------------------
# found these strings in some other malicious files via Google search.

$GETPASSWORD1:SIZE
$GETPASSWORD1:CAPTION
$GETPASSWORD1:IDC_PASSWORDENTER
$GETPASSWORD1:IDOK
$GETPASSWORD1:IDCANCEL
-------------------
sfxrar[.]exe # self-extracting archive
DeleteFileW # something is deleted when closed (probably an archive). 
-------------------
Path="C:/Serverwebcommon/" # 
BlockdriverhostPerf[.]exe # flagged as dcrat (see below).
-------------------
CreateEncryptor # creates a symmetric encryptor object.
get_CurrentDomain # relates to AD & gets user credentials
-------------------
# This looks like possible enumeration.

get_FullName
set_UseShellExecute
get_UtcNow
get_Millisecond
get_CurrentThread
get_ManagedThreadId
get_FileName
get_ExecutablePath
get_DirectoryName
get_ProcessName
get_Directory
get_DeviceName
get_OSVersion
get_VersionString
get_ProcessorCount
get_TotalSize
get_MachineName
get_UserName
get_Version
```

We solved the question: "Is it malicious or not?" from online research- as some of the strings correlated with other malware entries. However, the most notable flag was *BlockdriverhostPerf.exe*, which has an entry on Malware Bazaar: https://bazaar.abuse.ch/sample/c08c41059368f7b4b4e23384333d646b786b335a71516073c7a70a4b436f952f/

Note, I examined some keywords and observed from a high level. I'm not very knowledgeable with the different functions and resort to researching. There may be much more interesting strings that I missed.

* Running floss to see if additional intel is revealed:

```bash
remnux@remnux:~/static_analysis/dcrat_23MAR2024$ floss dcrat_23MAR2024exe.sample > dcrat_23MAR2024exe.floss.txt
```

Floss reveals some more interesting information, such as a string ```SpotifyStartupTask[.]exe``` -- Anyrun has a report on this:

* https://any.run/report/41971da9cb866aa19e6d70d62287f622bb79d9cbbee1a8a29c44ecc3b066afc6/8c889b3c-c4ee-424c-83a6-d64d50eba371
* DCrat, also known as Dark Crystal RAT, is a remote access trojan (RAT), which was first introduced in 2018. It is a modular malware that can be customized to perform different tasks. For instance, it can steal passwords, crypto wallet information, hijack Telegram and Steam accounts, and more. Attackers may use a variety of methods to distribute DCrat, but phishing email campaigns are the most common.*

Even "*DarkCrystal RAT*" is a revealed string I seen from floss output. The author possibly obfuscated a snippet of information about the program within the code- not entirely sure, as it's just the strings output.

<img src="https://i.postimg.cc/XvHXbP71/image.png">
# Yara

```bash
# resource (antidebug_antivm.yar): https://github.com/techbliss/Yara_Mailware_Quick_menu_scanner/blob/master/yara/antidebug_antivm.yar

SEH_Save # WindowsPE; condition: $a = { 64 ff 35 00 00 00 00 }

anti_dbg # (Checks if being debugged)
 	$d1 = "Kernel32.dll" nocase
    $c1 = "CheckRemoteDebuggerPresent"
    $c2 = "IsDebuggerPresent"
    $c3 = "OutputDebugString"
    $c4 = "ContinueDebugEvent"
    $c5 = "DebugActiveProcess"
    condition: $d1 and 1 of ($c*)

escalate_priv # (Escalade priviledges)
	$d1 = "Advapi32.dll" nocase
    $c1 = "SeDebugPrivilege" 
    $c2 = "AdjustTokenPrivileges" 
	condition: 1 of ($d*) and 1 of ($c*)

screenshot # (Take screenshot)
    $d1 = "Gdi32.dll" nocase
    $d2 = "User32.dll" nocase
    $c1 = "BitBlt" 
    $c2 = "GetDC" 
	condition: 1 of ($d*) and 1 of ($c*)
	
win_registry # (Affect system registries)
    $f1 = "advapi32.dll" nocase
    $c1 = "RegQueryValueExA"
    $c2 = "RegOpenKeyExA"
    $c3 = "RegCloseKey"
    $c4 = "RegSetValueExA"
    $c5 = "RegCreateKeyA"
    $c6 = "RegCloseKey" 
    condition: $f1 and 1 of ($c*)

win_token # (Affect system token)
	$f1 = "advapi32.dll" nocase
    $c1 = "DuplicateTokenEx"
    $c2 = "AdjustTokenPrivileges"
    $c3 = "OpenProcessToken"
    $c4 = "LookupPrivilegeValueA" 
    condition: $f1 and 1 of ($c*) 

win_files_operation # (Affect private profile)
	$f1 = "kernel32.dll" nocase
    $c1 = "WriteFile"
    $c2 = "SetFilePointer"
    $c3 = "WriteFile"
    $c4 = "ReadFile"
    $c5 = "DeleteFileA"
    $c6 = "CreateFileA"
    $c7 = "FindFirstFileA"
    $c8 = "MoveFileExA"
    $c9 = "FindClose"
    $c10 = "SetFileAttributesA"
    $c11 = "CopyFile"
	condition: $f1 and 3 of ($c*)

# resource: https://github.com/Yara-Rules/rules/blob/master/crypto/crypto_signatures.yar

Big_Numbers1 # (Looks for big numbers 32:sized) -- crypto signatures rules
	$c0 = /[0-9a-fA-F]{32}/ fullword wide ascii
	condition: $c0

Big_Numbers3 # (Looks for big numbers 64:sized)
	$c0 = /[0-9a-fA-F]{64}/ fullword wide ascii
	condition: $c0
	
CRC32_poly_Constant # Look for CRC32 [poly]

# Returns a 32-bit Cyclic Redundancy Check (CRC32) value. Use CRC32 to find data transmission errors. You can also use CRC32 if you want to verify that data stored in a file has not been modified.

	$c0 = { 2083B8ED }
	condition: $c0

MD5_Constants # (Look for MD5 constants)
// Init constants
	$c0 = { 67452301 }
	$c1 = { efcdab89 }
	$c2 = { 98badcfe }
	$c3 = { 10325476 }
	$c4 = { 01234567 }
	$c5 = { 89ABCDEF }
	$c6 = { FEDCBA98 }
	$c7 = { 76543210 }
	// Round 2
	$c8 = { F4D50d87 }
	$c9 = { 78A46AD7 }
	condition: 5 of them

RIPEMD160_Constants # (Look for RIPEMD-160 constants)
$c0 = { 67452301 }
	$c1 = { EFCDAB89 }
	$c2 = { 98BADCFE }
	$c3 = { 10325476 }
	$c4 = { C3D2E1F0 }
	$c5 = { 01234567 }
	$c6 = { 89ABCDEF }
	$c7 = { FEDCBA98 }
	$c8 = { 76543210 }
	$c9 = { F0E1D2C3 }
	condition: 5 of them

SHA1_Constants # (Look for SHA1 constants)
$c0 = { 67452301 }
	$c1 = { EFCDAB89 }
	$c2 = { 98BADCFE }
	$c3 = { 10325476 }
	$c4 = { C3D2E1F0 }
	$c5 = { 01234567 }
	$c6 = { 89ABCDEF }
	$c7 = { FEDCBA98 }
	$c8 = { 76543210 }
	$c9 = { F0E1D2C3 }

SHA2_BLAKE2_IVs # (Look for SHA2/BLAKE2/Argon2 IVs)
	$c0 = { 67 E6 09 6A }
	$c1 = { 85 AE 67 BB }
	$c2 = { 72 F3 6E 3C }
	$c3 = { 3A F5 4F A5 }
	$c4 = { 7F 52 0E 51 }
	$c5 = { 8C 68 05 9B }
	$c6 = { AB D9 83 1F }
	$c7 = { 19 CD E0 5B }
	$c10 = { D6C162CA }
	condition: all of them

RijnDael_AES_CHAR # (RijnDael AES (check2) [char])
	$c0 = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 CA 82 C9 7D FA 59 47       F0 AD D4 A2 AF 9C A4 72 C0 }

Contains_VBE_File # (Detect a VBE file inside a byte sequence)
# method = "Find string starting with #@~^ and ending with ^#~@"
	$vbe = /#@~\^.+\^#~@/
	condition: $vbe

maldoc_find_kernel32_base_method_1 # N/A description
	 $a1 = {64 8B (05|0D|15|1D|25|2D|35|3D) 30 00 00 00}
	 $a2 = {64 A1 30 00 00 00}
	 condition: any of them

IsPE32 # N/A description
	condition:
	// MZ signature at offset 0 and ...
	uint16(0) == 0x5A4D and
	// ... PE signature at offset stored in MZ header at 0x3C
	uint16(uint32(0x3C)+0x18) == 0x010B

IsWindowsGUI # (PECheck)
	condition:
	// MZ signature at offset 0 and ...
	uint16(0) == 0x5A4D and
	// ... PE signature at offset stored in MZ header at 0x3C
	uint16(uint32(0x3C)+0x5C) == 0x0002

# resource: https://github.com/x64dbg/yarasigs/blob/master/packer_compiler_signatures.yara

IsPacked # (PE ELF Check) 
	condition
	// MZ signature at offset 0 and ...
	((IsPE32 or IsPE64) or (IsELF32 or IsELF64)) and 
	math.entropy(0, filesize-pe.overlay.size) >= 7.0

HasOverlay # (PECheck)
	condition:
	// MZ signature at offset 0 and ...
	uint16(0) == 0x5A4D and
	// ... PE signature at offset stored in MZ header at 0x3C
	uint32(uint32(0x3C)) == 0x00004550 and
	//stupid check if last section is 0		
	//not (pe.sections[pe.number_of_sections-       1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) == 0x0 and

HasDebugData # (DebugData Check)
	condition
	// MZ signature at offset 0 and ...
	uint16(0) == 0x5A4D and
	// ... PE signature at offset stored in MZ header at 0x3C
	uint32(uint32(0x3C)) == 0x00004550 and
	//orginal
	//((uint32(uint32(0x3C)+0xA8) >0x0) and (uint32be(uint32(0x3C)+0xAC) >0x0))
	//((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) x64/x32
	(IsPE32 or IsPE64) and
	((uint32(uint32(0x3C)+0xA8+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5)) >0x0)   and (uint32be(uint32(0x3C)+0xAC+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5)) >0x0))

HasRichSignature # (Rich Signature Check)
	$a0 = "Rich" ascii
	condition:
	// MZ signature at offset 0 and ...
	uint16(0) == 0x5A4D and
	// ... PE signature at offset stored in MZ header at 0x3C
	uint32(uint32(0x3C)) == 0x00004550 and
	(for any of ($a*) : ($ in (0x0..uint32(0x3c) )))

VC8_Microsoft_Corporation 
Microsoft_Visual_Cpp_8
```

# peframe

```bash
remnux@remnux:~/static_analysis/dcrat_23MAR2024/analysis_outputs$ peframe dcrat_23MAR2024exe.sample > dcrat_23MAR2024exe.peframe.txt # done some organizing to my output directory- to include in repo once done playing with the various tools.
```

> This mostly outputs what we uncovered from the strings analysis, but there are a few quick references I'd like to copy over.

```
filename         dcrat_23MAR2024exe.sample
filetype         PE32 executable (GUI) Intel 80386, for MS Windows
filesize         1961714
hash sha256      ac15d82441447b30e13ba57c3c2ab12dae50e7396c74991393bd225f3784aab9
virustotal       /
imagebase        0x400000
entrypoint       0x1f530
imphash          12e12319f1029ec4f8fcbed7e82df162
datetime         2022-03-03 13:15:57
dll              False
directories      import, debug, tls, resources, relocations
sections         .rdata, .data, .didat, .text *, .rsrc *, .reloc *
features         mutex, antidbg, packer, crypto

Mutex Api---
WaitForSingleObject

Sections Suspicious---
.text            6.71
.rsrc            6.63
.reloc           6.62

Import function---
KERNEL32.dll     143
OLEAUT32.dll     3
gdiplus.dll      9

Possible Breakpoints---
CloseHandle
CreateDirectoryW
CreateFileMappingW
CreateFileW
CreateThread
DeleteCriticalSection
DeleteFileW
DeviceIoControl
ExitProcess
FindFirstFileExA
FindFirstFileW
FindNextFileA
FindNextFileW
FindResourceW
GetCommandLineA
GetCommandLineW
GetCurrentProcess
GetCurrentProcessId
GetFileAttributesW
GetModuleFileNameA
GetModuleFileNameW
GetModuleHandleExW
GetModuleHandleW
GetProcAddress
GetStartupInfoW
GetSystemDirectoryW
GetTempPathW
GetTickCount
GetVersionExW
HeapAlloc
InitializeCriticalSectionAndSpinCount
IsDebuggerPresent
LoadLibraryExA
LoadLibraryExW
LoadLibraryW
LockResource
MapViewOfFile
OpenFileMappingW
ReadFile
RemoveDirectoryW
SetFilePointer
SetFilePointerEx
Sleep
TerminateProcess
UnhandledExceptionFilter
VirtualProtect
WaitForSingleObject
WriteFile

URL---
[hXXp://]schemas[.]microsoft[.]com/SMI/2005/WindowsSettings

File---
USER32.dll          Library
GDI32.dll           Library
COMDLG32.dll        Library
ADVAPI32.dll        Library
SHELL32.dll         Library
ole32.dll           Library
SHLWAPI.dll         Library
COMCTL32.dll        Library
sfxrar.exe          Executable
KERNEL32.dll        Library
OLEAUT32.dll        Library
gdiplus.dll         Library
BlockdriverhostPerf.exe Executable
winmm.dll           Library
KernelBase.dll      Library
ktmw32.dll          Library
mscoree.dll         Library
