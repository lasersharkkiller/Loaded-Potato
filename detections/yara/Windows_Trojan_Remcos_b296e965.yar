
rule ELASTIC_Windows_Trojan_Remcos_B296E965 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Remcos (Windows.Trojan.Remcos)"
		author = "Elastic Security"
		id = "b296e965-a99e-4446-b969-ba233a2a8af4"
		date = "2021-06-10"
		modified = "2021-08-23"
		reference = "https://www.elastic.co/security-labs/exploring-the-ref2731-intrusion-set"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Remcos.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0ebeffa44bd1c3603e30688ace84ea638fbcf485ca55ddcfd6fbe90609d4f3ed"
		logic_hash = "069072abd1182eee50cb9937503d47845e7315d8e3cd6b63576adc8f21820c82"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a5267bc2dee28a3ef58beeb7e4a151699e3e561c16ce0ab9eb27de33c122664d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Remcos restarted by watchdog!" ascii fullword
		$a2 = "Mutex_RemWatchdog" ascii fullword
		$a3 = "%02i:%02i:%02i:%03i"
		$a4 = "* Remcos v" ascii fullword

	condition:
		2 of them
}
