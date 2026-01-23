
rule ELASTIC_Linux_Trojan_Mirai_77137320 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "77137320-6c7e-4bb8-81a4-bd422049c309"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L735-L753"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "91642663793bdda93928597ff1ac6087e4c1e5d020a8f40f2140e9471ab730f9"
		logic_hash = "ee48e0478845a61dbbdb5cc3ee5194eb272fcf6dcf139381f068c9af1557d0d4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "afeedf7fb287320c70a2889f43bc36a3047528204e1de45c4ac07898187d136b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 54 24 01 89 C7 31 F6 31 C9 48 89 A4 24 00 01 00 00 EB 1D 80 7A }

	condition:
		all of them
}
