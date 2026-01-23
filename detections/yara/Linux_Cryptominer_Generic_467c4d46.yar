
rule ELASTIC_Linux_Cryptominer_Generic_467C4D46 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "467c4d46-3272-452c-9251-3599d16fc916"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L821-L839"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "388b927b850b388e0a46a6c9a22b733d469e0f93dc053ebd78996e903b25e38a"
		logic_hash = "b28f871365c1fa6315b1c2fc6698bdd224961972cd578db05c311406c239ac22"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "cbde94513576fdb7cabf568bd8439f0194d6800373c3735844e26d262c8bc1cc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 49 8B 77 08 48 21 DE 4C 39 EE 75 CE 66 41 83 7F 1E 04 4C 89 F5 }

	condition:
		all of them
}