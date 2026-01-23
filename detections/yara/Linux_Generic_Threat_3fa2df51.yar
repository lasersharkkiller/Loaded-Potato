
rule ELASTIC_Linux_Generic_Threat_3Fa2Df51 : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "3fa2df51-fa0e-4149-8631-fa4bfb2fe66e"
		date = "2024-05-21"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L1194-L1213"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "89ec224db6b63936e8bc772415d785ef063bfd9343319892e832034696ff6f15"
		logic_hash = "f43b659dd093a635d9723b2443366763132217aaf28c582ed43f180725f92f19"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "3aa2bbc4e177574fa2ae737e6f27b92caa9a83e6e9a1704599be67e2c3482f6a"
		severity = 50
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 5B 6B 77 6F 72 6B 65 72 2F 30 3A 32 5D }
		$a2 = { 2F 74 6D 70 2F 6C 6F 67 5F 64 65 2E 6C 6F 67 }

	condition:
		all of them
}
