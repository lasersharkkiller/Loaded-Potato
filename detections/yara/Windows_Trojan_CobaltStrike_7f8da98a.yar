
rule ELASTIC_Windows_Trojan_Cobaltstrike_7F8Da98A : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Cobaltstrike (Windows.Trojan.CobaltStrike)"
		author = "Elastic Security"
		id = "7f8da98a-3336-482b-91da-82c7cef34c62"
		date = "2023-05-09"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CobaltStrike.yar#L1058-L1076"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e3bc2bec4a55ad6cfdf49e5dbd4657fc704af1758ca1d6e31b83dcfb8bf0f89d"
		logic_hash = "6c8698d65cbbf893f79ca1de5273535891418c87c234a2542f5f8079e56d9507"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "c375492960a6277bf665bea86302cec774c0d79506e5cb2e456ce59f5e68aa2e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4D 53 53 45 2D 25 64 2D 73 65 72 76 65 72 }

	condition:
		all of them
}
