rule ELASTIC_Macos_Cryptominer_Generic_333129B7 : FILE MEMORY
{
	meta:
		description = "Detects Macos Cryptominer Generic (MacOS.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "333129b7-8137-4641-bd86-ebcf62257d7b"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/MacOS_Cryptominer_Generic.yar#L23-L41"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "bf47d27351d6b0be0ffe1d6844e87fe8f4f4d33ea17b85c11907266d36e4b827"
		logic_hash = "ce434e7d3516452b6cad762ee9ff0a0f1ec47b5c35c83ac78858f897323f7de7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "baa9e777683d31c27170239752f162799a511bf40269a06a2eab8971fabb098a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 6D BF 81 55 D4 4C D4 19 4C 81 18 24 3C 14 3C 30 14 18 26 79 5F 35 5F 4C 35 26 }

	condition:
		all of them
}

