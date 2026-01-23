
rule ELASTIC_Windows_Trojan_Vidar_32Fea8Da : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Vidar (Windows.Trojan.Vidar)"
		author = "Elastic Security"
		id = "32fea8da-b381-459c-8bf4-696388b8edcc"
		date = "2023-05-04"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Vidar.yar#L46-L66"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6f5c24fc5af2085233c96159402cec9128100c221cb6cb0d1c005ced7225e211"
		logic_hash = "1a18cdc3bd533c34eb05b239830ecec418dc76ee9f4fcfc48afc73b07d55b3cd"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "ebcced7b2924cc9cfe9ed5b5f84a8959e866a984f2b5b6e1ec5b1dd096960325"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 4F 4B 58 20 57 65 62 33 20 57 61 6C 6C 65 74 }
		$a2 = { 8B E5 5D C3 5E B8 03 00 00 00 5B 8B E5 5D C3 5E B8 08 00 00 }
		$a3 = { 83 79 04 00 8B DE 74 08 8B 19 85 DB 74 62 03 D8 8B 03 85 C0 }

	condition:
		all of them
}
