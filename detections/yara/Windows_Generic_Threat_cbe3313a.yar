
rule ELASTIC_Windows_Generic_Threat_Cbe3313A : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "cbe3313a-ab8f-4bf1-8f62-b5494c6e7034"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1607-L1625"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1ca2a28c851070b9bfe1f7dd655f2ea10ececef49276c998a1d2a1b48f84cef3"
		logic_hash = "41a731cefe0c8ee95f1db598b68a8860ef7ff06137ce94d0dd0b5c60c4240e85"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dc92cec72728b1df78d79dc5a34ea56ee0b8c8199652c1039288c46859799376"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 EC 08 68 E6 25 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 2C 53 56 57 89 65 F8 C7 45 FC D0 25 40 00 A1 94 B1 41 00 33 F6 3B C6 89 75 EC 89 75 E8 89 75 E4 0F 8E E7 00 00 }

	condition:
		all of them
}
