
rule ELASTIC_Windows_Trojan_Cobaltstrike_3Dc22D14 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Cobaltstrike (Windows.Trojan.CobaltStrike)"
		author = "Elastic Security"
		id = "3dc22d14-a2f4-49cd-a3a8-3f071eddf028"
		date = "2023-05-09"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CobaltStrike.yar#L1037-L1056"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7898194ae0244611117ec948eb0b0a5acbc15cd1419b1ecc553404e63bc519f9"
		logic_hash = "2f52cd5f3b782c28e372c3daa9b7ddc4d2b9f68832f5250983412c2e7a755e73"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0e029fac50ffe8ea3fc5bc22290af69e672895eaa8a1b9f3e9953094c133392c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
		$a2 = "%s as %s\\%s: %d" fullword

	condition:
		all of them
}
