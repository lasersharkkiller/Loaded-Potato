
rule ELASTIC_Windows_Trojan_Generic_73Ed7375 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Generic (Windows.Trojan.Generic)"
		author = "Elastic Security"
		id = "73ed7375-c8ab-4d95-ae66-62b1b02a3d1e"
		date = "2023-05-09"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Generic.yar#L177-L196"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2b17328a3ef0e389419c9c86f81db4118cf79640799e5c6fdc97de0fc65ad556"
		logic_hash = "7e27c9377d0b2058a2a36da4ac7d37a54c566f3246e69aa356171edae6b478c5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a026cc2db3bfebca4b4ea6e9dc41c2b18d0db730754ef3131d812d7ef9cd17d6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 48 8B 03 48 8B CE 49 8D 54 04 02 41 FF D6 48 89 03 48 83 C3 08 48 }
		$a2 = { 41 3C 42 8B BC 08 88 00 00 00 46 8B 54 0F 20 42 8B 5C 0F 24 4D }

	condition:
		all of them
}
