
rule ELASTIC_Windows_Trojan_Redlinestealer_63E7E006 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Redlinestealer (Windows.Trojan.RedLineStealer)"
		author = "Elastic Security"
		id = "63e7e006-6c0c-47d8-8090-a6b36f01f3a3"
		date = "2023-05-01"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_RedLineStealer.yar#L84-L104"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e062c99dc9f3fa780ea9c6249fa4ef96bbe17fd1df38dbe11c664a10a92deece"
		logic_hash = "2085eaf622b52372124e9b23d19e3e4a7fdb7a4559ad9a09216c1cbae96ca5b6"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "47c7b9a39a5e0a41f26fdf328231eb173a51adfc00948c68332ce72bc442e19e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 30 68 44 27 25 5B 3D 79 21 54 3A }
		$a2 = { 40 5E 30 33 5D 44 34 4A 5D 48 33 }
		$a3 = { 4B EF 4D FF 44 DD 41 70 44 DC 41 00 44 DC 41 03 43 D9 3E 00 44 }

	condition:
		all of them
}
