
rule ELASTIC_Windows_Trojan_Metasploit_91Bc5D7D : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Metasploit (Windows.Trojan.Metasploit)"
		author = "Elastic Security"
		id = "91bc5d7d-31e3-4c02-82b3-a685194981f3"
		date = "2021-08-02"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Metasploit.yar#L208-L226"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0dd993ff3917dc56ef02324375165f0d66506c5a9b9548eda57c58e041030987"
		logic_hash = "74154902b03c36a4ee9bc54ae9399bae9e6afb7fe8d0fe232b88250afc368d6f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8848a3de66a25dd98278761a7953f31b7995e48621dec258f3d92bd91a4a3aa3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 49 BE 77 73 32 5F 33 32 00 00 41 56 49 89 E6 48 81 EC A0 01 00 00 49 89 E5 }

	condition:
		all of them
}
