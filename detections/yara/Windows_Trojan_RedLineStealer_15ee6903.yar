
rule ELASTIC_Windows_Trojan_Redlinestealer_15Ee6903 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Redlinestealer (Windows.Trojan.RedLineStealer)"
		author = "Elastic Security"
		id = "15ee6903-757f-462b-8e1c-1ed8ca667910"
		date = "2023-05-04"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_RedLineStealer.yar#L147-L166"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "46b506cafb2460ca2969f69bcb0ee0af63b6d65e6b2a6249ef7faa21bde1a6bd"
		logic_hash = "22c8a1f4b5b94261cfabdbcc00e45b9437a0132d4e9d4543b734d4f303336696"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "d3a380f68477b98b3f5adc11cc597042aa95636cfec0b0a5f2e51c201aa61227"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 53 65 65 6E 42 65 66 6F 72 65 33 }
		$a2 = { 73 65 74 5F 53 63 61 6E 47 65 63 6B 6F 42 72 6F 77 73 65 72 73 50 61 74 68 73 }

	condition:
		all of them
}
