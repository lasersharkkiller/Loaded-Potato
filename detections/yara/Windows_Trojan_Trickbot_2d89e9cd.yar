
rule ELASTIC_Windows_Trojan_Trickbot_2D89E9Cd : FILE MEMORY
{
	meta:
		description = "Targets tabDll64.dll module containing functionality using SMB for lateral movement"
		author = "Elastic Security"
		id = "2d89e9cd-2941-4b20-ab4e-a487d329ff76"
		date = "2021-03-29"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L741-L785"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3963649ebfabe8f6277190be4300ecdb68d4b497ac5f81f38231d3e6c862a0a8"
		logic_hash = "c15833687c2aed55aae0bb5de83c088cb66edeb4ad1964543522f5477c1f1942"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "e6eea38858cfbbe5441b1f69c5029ff9279e7affa51615f6c91981fe656294fc"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "[INJECT] inject_via_remotethread_wow64: pExecuteX64( pX64function, ctx ) failed" ascii fullword
		$a2 = "[INJECT] inject_via_remotethread_wow64: VirtualAlloc pExecuteX64 failed" ascii fullword
		$a3 = "%SystemRoot%\\system32\\stsvc.exe" ascii fullword
		$a4 = "[INJECT] inject_via_remotethread_wow64: pExecuteX64=0x%08p, pX64function=0x%08p, ctx=0x%08p" ascii fullword
		$a5 = "DLL and target process must be same architecture" ascii fullword
		$a6 = "[INJECT] inject_via_remotethread_wow64: VirtualAlloc pX64function failed" ascii fullword
		$a7 = "%SystemDrive%\\stsvc.exe" ascii fullword
		$a8 = "Wrote shellcode to 0x%x" ascii fullword
		$a9 = "ERROR: %d, line - %d" wide fullword
		$a10 = "[INJECT] inject_via_remotethread_wow64: Success, hThread=0x%08p" ascii fullword
		$a11 = "GetProcessPEB:EXCEPT" wide fullword
		$a12 = "Checked count - %i, connected count %i" wide fullword
		$a13 = "C:\\%s\\%s C:\\%s\\%s" ascii fullword
		$a14 = "C:\\%s\\%s" ascii fullword
		$a15 = "%s\\ADMIN$\\stsvc.exe" wide fullword
		$a16 = "%s\\C$\\stsvc.exe" wide fullword
		$a17 = "Size - %d kB" ascii fullword
		$a18 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"dpost"
		$a19 = "%s - FAIL" wide fullword
		$a20 = "%s - SUCCESS" wide fullword
		$a21 = "CmainSpreader::init() CreateEvent, error code %i" wide fullword
		$a22 = "Incorrect ModuleHandle %i, expect %i" wide fullword
		$a23 = "My interface is \"%i.%i.%i.%i\", mask \"%i.%i.%i.%i\"" wide fullword
		$a24 = "WormShare" ascii fullword
		$a25 = "ModuleHandle 0x%08X, call Control: error create thread %i" wide fullword
		$a26 = "Enter to Control: moduleHandle 0x%08X, unknown Ctl = \"%S\"" wide fullword

	condition:
		3 of ($a*)
}
