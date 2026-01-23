
rule ELASTIC_Windows_Trojan_Plugx_F338Dab5 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Plugx (Windows.Trojan.PlugX)"
		author = "Elastic Security"
		id = "f338dab5-8c8f-46d7-8f93-48077fc76da1"
		date = "2024-06-05"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_PlugX.yar#L25-L45"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8af3fc1f8bd13519d78ee83af43daaa8c5e2c3f184c09f5c41941e0c6f68f0f7"
		logic_hash = "0482305a73bc500aa7c266536cb8286ea796f6b1eaba39547bed22313bbb4457"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7c9f3d739eb17c545ded116387400340117acc23f3ef9fec9eacf993f1d2eb80"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 45 08 FF B0 60 03 00 00 E8 A8 0C 00 00 83 C4 24 8D 45 08 89 }
		$a2 = { 2C 5E 5F 5B 5D C3 CC 55 53 57 56 83 EC 10 8B 6C 24 30 8B 44 }
		$a3 = { 89 4D D4 83 60 04 00 3B F3 75 40 E8 53 DA FF FF 8B 40 08 89 }

	condition:
		2 of them
}
