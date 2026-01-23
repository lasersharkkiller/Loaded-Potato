
rule ELASTIC_Windows_Generic_Threat_E8Abb835 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "e8abb835-f0c1-4e27-a0ca-3a3cae3362df"
		date = "2024-03-26"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3344-L3362"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e42262671325bec300afa722cefb584e477c3f2782c8d4c6402d6863df348cac"
		logic_hash = "0ad56b8c741a79a600a0d5588c4e8760a6d19fef72ff7814a00cfb84a90f23aa"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ca8c2f4b16ebe1bb48c91a536d8aca98bed5592675eff9311e77d7e06dfe3c5b"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 48 81 EC 28 05 00 00 66 44 0F 7F 84 24 10 05 00 00 66 0F 7F BC 24 00 05 00 00 0F 29 B4 24 F0 04 00 00 44 89 44 24 74 48 89 94 24 C8 00 00 00 48 89 CB 48 C7 44 24 78 00 00 00 00 0F 57 F6 0F 29 }

	condition:
		all of them
}
