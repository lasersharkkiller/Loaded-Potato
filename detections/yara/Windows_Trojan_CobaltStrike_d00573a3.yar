
rule ELASTIC_Windows_Trojan_Cobaltstrike_D00573A3 : FILE MEMORY
{
	meta:
		description = "Identifies Screenshot module from Cobalt Strike"
		author = "Elastic Security"
		id = "d00573a3-db26-4e6b-aabf-7af4a818f383"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CobaltStrike.yar#L599-L625"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "e458d41d28b76c989af6385f183f33aa9e11b93e529f032e95bd75433b80bd69"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b6fa0792b99ea55f359858d225685647f54b55caabe53f58b413083b8ad60e79"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "screenshot.x64.dll" ascii fullword
		$a2 = "screenshot.dll" ascii fullword
		$a3 = "\\\\.\\pipe\\screenshot" ascii fullword
		$b1 = "1I1n1Q3M5Q5U5Y5]5a5e5i5u5{5" ascii fullword
		$b2 = "GetDesktopWindow" ascii fullword
		$b3 = "CreateCompatibleBitmap" ascii fullword
		$b4 = "GDI32.dll" ascii fullword
		$b5 = "ReflectiveLoader"
		$b6 = "Adobe APP14 marker: version %d, flags 0x%04x 0x%04x, transform %d" ascii fullword

	condition:
		2 of ($a*) or 5 of ($b*)
}
