
rule ELASTIC_Linux_Trojan_Mirai_B14F4C5D : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "b14f4c5d-054f-46e6-9fa8-3588f1ef68b7"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L180-L197"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "1a2114a7b397c850d732940a0e154bc04fbee1fdc12d343947b343b9b27a8af1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a70d052918dd2fbc66db241da6438015130f0fb6929229bfe573546fe98da817"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 53 31 DB 8B 4C 24 0C 8B 54 24 08 83 F9 01 76 15 66 8B 02 83 E9 02 25 FF FF 00 00 83 C2 02 01 C3 83 F9 01 77 EB 49 75 05 0F BE 02 01 C3 }

	condition:
		all of them
}
