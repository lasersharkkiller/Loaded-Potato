
rule ELASTIC_Windows_Rootkit_R77_5Bab748B : FILE MEMORY
{
	meta:
		description = "Detects Windows Rootkit R77 (Windows.Rootkit.R77)"
		author = "Elastic Security"
		id = "5bab748b-8576-4967-9b50-a3778db1dd71"
		date = "2022-03-04"
		modified = "2022-04-12"
		reference = "https://www.elastic.co/security-labs/elastic-security-labs-steps-through-the-r77-rootkit"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Rootkit_R77.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "cfc76dddc74996bfbca6d9076d2f6627912ea196fdbdfb829819656d4d316c0c"
		logic_hash = "ebf851ef41fde8e3118acc742cd2b38651f662a00f11dd6f7c65cf56019c43d5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2523d25c46bbb9621f0eceeda10aff31e236ed0bf03886de78524bdd2d39cfaa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 01 04 10 41 8B 4A 04 49 FF C1 48 8D 41 F8 48 D1 E8 4C 3B C8 }

	condition:
		all of them
}
