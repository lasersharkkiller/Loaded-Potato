
rule ELASTIC_Linux_Trojan_Mirai_5C62E6B2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "5c62e6b2-9f6a-4c6d-b3fc-c6cbc8cf0b4b"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L617-L635"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "91642663793bdda93928597ff1ac6087e4c1e5d020a8f40f2140e9471ab730f9"
		logic_hash = "6505c4272f0f7c8c5f2d3f7cefdc3947c4015b0dfd94efde4357a506af93a99d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "39501003c45c89d6a08f71fbf9c442bcc952afc5f1a1eb7b5af2d4b7633698a8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FF C1 83 F9 05 7F 14 48 63 C1 48 89 94 C4 00 01 00 00 FF C6 48 }

	condition:
		all of them
}
