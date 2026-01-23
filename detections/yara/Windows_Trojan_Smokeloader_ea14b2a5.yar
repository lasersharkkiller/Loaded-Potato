
rule ELASTIC_Windows_Trojan_Smokeloader_Ea14B2A5 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Smokeloader (Windows.Trojan.Smokeloader)"
		author = "Elastic Security"
		id = "ea14b2a5-ea0d-4da2-8190-dbfcda7330d9"
		date = "2023-05-03"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Smokeloader.yar#L41-L60"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "15fe237276b9c2c6ceae405c0739479d165b406321891c8a31883023e7b15d54"
		logic_hash = "8a96985902f82979f1512d4d30cfa41fd23562b8f86bf2f722351ef2adf4365f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "950ce9826fdff209b6e03c70a4f78b812d211a2a9de84bec0e5efe336323001b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { AC 41 80 01 AC 41 80 00 AC 41 80 00 AC 41 C0 00 AC 41 80 01 }
		$a2 = { AC 41 80 00 AC 41 80 07 AC 41 80 00 AC 41 80 00 AC 41 80 00 }

	condition:
		all of them
}
