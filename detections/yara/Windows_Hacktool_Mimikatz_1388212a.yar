
rule ELASTIC_Windows_Hacktool_Mimikatz_1388212A : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Mimikatz (Windows.Hacktool.Mimikatz)"
		author = "Elastic Security"
		id = "1388212a-2146-4565-b93d-4555a110364f"
		date = "2021-04-13"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_Mimikatz.yar#L1-L43"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "66b4a0681cae02c302a9b6f1d611ac2df8c519d6024abdb506b4b166b93f636a"
		logic_hash = "1b717453810455e3f530e399f5f9f163d1ad0d71a5464fa5c68aa82edd699cda"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "dbbdc492c07e3b95d677044751ee4365ec39244e300db9047ac224029dfe6ab7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "   Password: %s" wide fullword
		$a2 = "  * Session Key   : 0x%08x - %s" wide fullword
		$a3 = "   * Injecting ticket : " wide fullword
		$a4 = " ## / \\ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )" wide fullword
		$a5 = "Remove mimikatz driver (mimidrv)" wide fullword
		$a6 = "mimikatz(commandline) # %s" wide fullword
		$a7 = "  Password: %s" wide fullword
		$a8 = " - SCardControl(FEATURE_CCID_ESC_COMMAND)" wide fullword
		$a9 = " * to 0 will take all 'cmd' and 'mimikatz' process" wide fullword
		$a10 = "** Pass The Ticket **" wide fullword
		$a11 = "-> Ticket : %s" wide fullword
		$a12 = "Busylight Lync model (with bootloader)" wide fullword
		$a13 = "mimikatz.log" wide fullword
		$a14 = "Log mimikatz input/output to file" wide fullword
		$a15 = "ERROR kuhl_m_dpapi_masterkey ; kull_m_dpapi_unprotect_domainkey_with_key" wide fullword
		$a16 = "ERROR kuhl_m_lsadump_dcshadow ; unable to start the server: %08x" wide fullword
		$a17 = "ERROR kuhl_m_sekurlsa_pth ; GetTokenInformation (0x%08x)" wide fullword
		$a18 = "ERROR mimikatz_doLocal ; \"%s\" module not found !" wide fullword
		$a19 = "Install and/or start mimikatz driver (mimidrv)" wide fullword
		$a20 = "Target: %hhu (0x%02x - %s)" wide fullword
		$a21 = "mimikatz Ho, hey! I'm a DC :)" wide fullword
		$a22 = "mimikatz service (mimikatzsvc)" wide fullword
		$a23 = "[masterkey] with DPAPI_SYSTEM (machine, then user): " wide fullword
		$a24 = "$http://blog.gentilkiwi.com/mimikatz 0" ascii fullword
		$a25 = " * Username : %wZ" wide fullword

	condition:
		3 of ($a*)
}
