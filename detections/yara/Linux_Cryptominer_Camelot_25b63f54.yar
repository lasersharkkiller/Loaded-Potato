
rule ELASTIC_Linux_Cryptominer_Camelot_25B63F54 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Camelot (Linux.Cryptominer.Camelot)"
		author = "Elastic Security"
		id = "25b63f54-8a32-4866-8f90-b2949f5e7539"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Camelot.yar#L119-L136"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "640ffe2040e382ad536c1b6947e05f8c25ff82897ef7ac673a7676815856a346"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c0bc4f5fc0ad846a90e214dfca8252bf096463163940930636c1693c7f3833fa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0F 6F 39 66 41 0F 6F 32 66 4D 0F 7E C3 66 44 0F D4 CB 66 45 0F }

	condition:
		all of them
}
