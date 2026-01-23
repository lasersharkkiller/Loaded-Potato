
rule ELASTIC_Linux_Trojan_Mirai_389Ee3E9 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "389ee3e9-70c1-4c93-a999-292cf6ff1652"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1782-L1800"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5217f2a46cb93946e04ab00e385ad0fe0a2844b6ea04ef75ee9187aac3f3d52f"
		logic_hash = "fedeae98d468a11c3eaa561b9d5433ec206bdd4caed5aed7926434730f7f866b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "59f2359dc1f41d385d639d157b4cd9fc73d76d8abb7cc09d47632bb4c9a39e6e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 45 00 EB 2C 8B 4B 04 8B 13 8B 7B 18 8B 01 01 02 8B 02 83 }

	condition:
		all of them
}
