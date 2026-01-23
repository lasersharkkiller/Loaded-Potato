
rule ELASTIC_Linux_Trojan_Mirai_Ac253E4F : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "ac253e4f-b628-4dd0-91f1-f19099286992"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1303-L1321"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "91642663793bdda93928597ff1ac6087e4c1e5d020a8f40f2140e9471ab730f9"
		logic_hash = "1ab463fce01148c2cc95659fdf8b05e597d9b4eeabe81a9cdfa1da3632d72291"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e2eee1f72b8c2dbf68e57b721c481a5cd85296e844059decc3548e7a6dc28fea"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 31 C9 EB 0A 6B C1 0A 0F BE D2 8D 4C 02 D0 8A 17 48 FF C7 8D }

	condition:
		all of them
}
