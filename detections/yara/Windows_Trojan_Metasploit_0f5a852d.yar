
rule ELASTIC_Windows_Trojan_Metasploit_0F5A852D : FILE MEMORY
{
	meta:
		description = "Identifies 64 bit metasploit wininet reverse shellcode. May also be used by other malware families."
		author = "Elastic Security"
		id = "0f5a852d-cacd-43d7-8754-204b09afba2f"
		date = "2021-04-07"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Metasploit.yar#L101-L119"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "11cddf2191a2f70222a0c8c591e387b4b5667bc432a2f686629def9252361c1d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "97daac4249e85a73d4e6a4450248e59e0d286d5e7c230cf32a38608f8333f00d"
		threat_name = "Windows.Trojan.Metasploit"
		severity = 80
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 49 BE 77 69 6E 69 6E 65 74 00 41 56 48 89 E1 49 C7 C2 4C 77 26 07 FF D5 }

	condition:
		all of them
}
