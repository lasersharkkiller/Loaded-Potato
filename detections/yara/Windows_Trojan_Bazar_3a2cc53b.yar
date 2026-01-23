
rule ELASTIC_Windows_Trojan_Bazar_3A2Cc53B : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bazar (Windows.Trojan.Bazar)"
		author = "Elastic Security"
		id = "3a2cc53b-4f73-41f9-aabd-08b8755ba44c"
		date = "2021-06-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Bazar.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b057eb94e711995fd5fd6c57aa38a243575521b11b98734359658a7a9829b417"
		logic_hash = "8cde37be646dbcf7e7f5e3f28f0fe8c95480861c62fa2ee8cdd990859313756c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f146d4fff29011acf595f2cba10ed7c3ce6ba07fbda0864d746f8e6355f91add"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 48 63 41 3C 45 33 ED 44 8B FA 48 8B F9 8B 9C 08 88 00 00 00 44 8B A4 08 8C 00 }

	condition:
		all of them
}
