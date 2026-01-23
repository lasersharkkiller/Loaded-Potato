rule BINARYALERT_Hacktool_Windows_Moyix_Creddump
{
	meta:
		description = "creddump is a python tool to extract credentials and secrets from Windows registry hives."
		author = "@mimeframe"
		id = "46df781a-abab-5593-99f9-1a6b993904cb"
		date = "2017-09-12"
		modified = "2017-09-12"
		reference = "https://github.com/moyix/creddump"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/windows/hacktool_windows_moyix_creddump.yara#L1-L16"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "3f2f4c5069fcb3d3b1d293a471bcf9489f058f27cd385885ab2bb4f719a3bd9d"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%" wide ascii
		$a2 = "0123456789012345678901234567890123456789" wide ascii
		$a3 = "NTPASSWORD" wide ascii
		$a4 = "LMPASSWORD" wide ascii
		$a5 = "aad3b435b51404eeaad3b435b51404ee" wide ascii
		$a6 = "31d6cfe0d16ae931b73c59d7e0c089c0" wide ascii

	condition:
		all of ($a*)
}

