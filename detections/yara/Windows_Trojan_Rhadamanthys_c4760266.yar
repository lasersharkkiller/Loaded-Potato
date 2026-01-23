
rule ELASTIC_Windows_Trojan_Rhadamanthys_C4760266 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Rhadamanthys (Windows.Trojan.Rhadamanthys)"
		author = "Elastic Security"
		id = "c4760266-bbff-4428-a7a5-bca7513c7993"
		date = "2024-06-05"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Rhadamanthys.yar#L99-L117"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "05074675b07feb8e7556c5af449f5e677e0fabfb09b135971afbb11743bf3165"
		logic_hash = "b8c1c56681aac4e1b1741dfa3ea929677214873b6f1795423a80742f699249de"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "53a04d385ef3a59b76500effaf740cd0e7d825ea5515f871097d82899b0cfc44"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 55 8B EC 83 EC 14 83 7D 08 00 53 8B D8 74 50 56 57 8B 7D 0C 6A 10 2B FB 5E 56 8D 45 EC 53 50 ?? ?? ?? ?? ?? 83 C4 0C 90 8B 4D 10 8B C3 2B CB 89 75 FC 8A 14 07 32 10 88 14 01 40 FF 4D FC 75 F2 }

	condition:
		all of them
}
