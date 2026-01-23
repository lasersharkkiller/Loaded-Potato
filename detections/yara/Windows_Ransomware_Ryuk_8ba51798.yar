
rule ELASTIC_Windows_Ransomware_Ryuk_8Ba51798 : BETA FILE MEMORY
{
	meta:
		description = "Identifies RYUK ransomware"
		author = "Elastic Security"
		id = "8ba51798-15d7-4f02-97fa-1844465ae9d8"
		date = "2020-04-30"
		modified = "2021-08-23"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Ryuk.yar#L111-L137"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "0733ae6a7e38bc2a25aa76a816284482d3ee25626559ec5af554b5f5070e534a"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "8e284bc6015502577a6ddd140b9cd110fd44d4d2cb55d0fdec5bebf3356fd7b3"
		threat_name = "Windows.Ransomware.Ryuk"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$c1 = "/v \"svchos\" /f" wide fullword
		$c2 = "cmd /c \"WMIC.exe shadowcopy delet\"" ascii fullword
		$c3 = "lsaas.exe" wide fullword
		$c4 = "FA_Scheduler" wide fullword
		$c5 = "ocautoupds" wide fullword
		$c6 = "CNTAoSMgr" wide fullword
		$c7 = "hrmlog" wide fullword
		$c8 = "UNIQUE_ID_DO_NOT_REMOVE" wide fullword

	condition:
		3 of ($c*)
}
