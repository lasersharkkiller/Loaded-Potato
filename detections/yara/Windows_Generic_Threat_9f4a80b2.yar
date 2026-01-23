
rule ELASTIC_Windows_Generic_Threat_9F4A80B2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "9f4a80b2-e1ee-4825-a5e5-79175213da7d"
		date = "2024-01-24"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2091-L2109"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "47d57d00e2de43f33cd56ff653adb59b804e4dbe37304a5fa6a202ee20b50c24"
		logic_hash = "1df3b8245bc0e995443d598feb5fe2605e05df64b863d4f47c17ecbe8d28c3ea"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "86946aea009f8debf5451ae7894529dbcf79ec104a51590d542c0d64a06f2669"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 28 00 00 0A 2A 20 02 00 00 00 FE 0E 08 00 00 FE 0C 08 00 20 00 00 00 00 FE 01 39 0A 00 00 00 00 20 01 00 00 00 FE 0E 08 00 00 FE 0C 08 00 20 02 00 00 00 FE 01 39 05 00 00 00 38 05 00 00 00 38 }

	condition:
		all of them
}
