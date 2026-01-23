
rule ELASTIC_Linux_Trojan_Winnti_6F4Ca425 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Winnti (Linux.Trojan.Winnti)"
		author = "Elastic Security"
		id = "6f4ca425-5cd2-4c22-b017-b5fc02b3abc2"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "161af780209aa24845863f7a8120aa982aa811f16ec04bcd797ed165955a09c1"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Winnti.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "a1ffc0e3d27c4bb9fd10f14d45b649b4f059c654b31449013ac06d0981ed25ed"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dec25af33fc004de3a1f53e0c3006ff052f7c51c95f90be323b281590da7d924"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 E5 48 89 7D D8 48 8B 45 D8 0F B6 40 27 0F BE C0 89 45 F8 48 8B }

	condition:
		all of them
}
