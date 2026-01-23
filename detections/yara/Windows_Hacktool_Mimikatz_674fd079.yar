
rule ELASTIC_Windows_Hacktool_Mimikatz_674Fd079 : FILE MEMORY
{
	meta:
		description = "Detection for default mimikatz memssp module"
		author = "Elastic Security"
		id = "674fd079-f7fe-4d89-87e7-ac11aa21c9ed"
		date = "2021-04-14"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_Mimikatz.yar#L45-L77"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "66b4a0681cae02c302a9b6f1d611ac2df8c519d6024abdb506b4b166b93f636a"
		logic_hash = "f63f3de05dd4f4f40cda6df67b75e37d7baa82c4b4cafd3ebdca35adfb0b15f8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b8f71996180e5f03c10e39eb36b2084ecaff78d7af34bd3d0d75225d2cfad765"
		threat_name = "Windows.Hacktool.Mimikatz"
		severity = 99
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 44 30 00 38 00 }
		$a2 = { 48 78 00 3A 00 }
		$a3 = { 4C 25 00 30 00 }
		$a4 = { 50 38 00 78 00 }
		$a5 = { 54 5D 00 20 00 }
		$a6 = { 58 25 00 77 00 }
		$a7 = { 5C 5A 00 5C 00 }
		$a8 = { 60 25 00 77 00 }
		$a9 = { 64 5A 00 09 00 }
		$a10 = { 6C 5A 00 0A 00 }
		$a11 = { 68 25 00 77 00 }
		$a12 = { 68 25 00 77 00 }
		$a13 = { 6C 5A 00 0A 00 }
		$b1 = { 6D 69 6D 69 C7 84 24 8C 00 00 00 6C 73 61 2E C7 84 24 90 00 00 00 6C 6F 67 }

	condition:
		all of ($a*) or $b1
}
