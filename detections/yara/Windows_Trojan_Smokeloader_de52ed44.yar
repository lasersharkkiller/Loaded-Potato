
rule ELASTIC_Windows_Trojan_Smokeloader_De52Ed44 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Smokeloader (Windows.Trojan.Smokeloader)"
		author = "Elastic Security"
		id = "de52ed44-062c-4b0d-9a41-1bfc31a8daa9"
		date = "2023-05-04"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Smokeloader.yar#L62-L81"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c689a384f626616005d37a94e6a5a713b9eead1b819a238e4e586452871f6718"
		logic_hash = "95a60079a316016ca3f78f18e7920b962f5770bef4211dd70e37f45bbe069406"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "950db8f87a81ef05cc2ecbfa174432ab31a3060c464836f3b38448bd8e5801be"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 08 31 FF 89 7D CC 66 8C E8 66 85 C0 74 03 FF 45 CC FF 53 48 }
		$a2 = { B0 8F 45 C8 8D 45 B8 89 38 8D 4D C8 6A 04 57 6A 01 51 57 57 }

	condition:
		all of them
}
