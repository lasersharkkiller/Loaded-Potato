
rule ELASTIC_Windows_Trojan_Metasploit_24338919 : FILE MEMORY
{
	meta:
		description = "Identifies metasploit wininet reverse shellcode. Also used by other tools (like beacon)."
		author = "Elastic Security"
		id = "24338919-8efe-4cf2-a23a-a3f22095b42d"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Metasploit.yar#L81-L99"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "af8cceebdebca863019860afca5d7c6400b68c8450bc17b7d7b74aeab2d62d16"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ac76190a84c4bdbb6927c5ad84a40e2145ca9e76369a25ac2ffd727eefef4804"
		threat_name = "Windows.Trojan.Metasploit"
		severity = 80
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }

	condition:
		$a1
}
