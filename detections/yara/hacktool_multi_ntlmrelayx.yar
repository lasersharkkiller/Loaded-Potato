rule BINARYALERT_Hacktool_Multi_Ntlmrelayx
{
	meta:
		description = "No description has been set in the source file - BinaryAlert"
		author = "@mimeframe"
		id = "7e0bc28f-9cb7-5c09-aedc-d95af23454aa"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://github.com/CoreSecurity/impacket/blob/master/examples/ntlmrelayx.py"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/multi/hacktool_multi_ntlmrelayx.yara#L1-L15"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "0d5d2d38866eb243e1803c456944e887d9d3920c54b15fd658bf90831fd87bfa"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "Started interactive SMB client shell via TCP" wide ascii
		$a2 = "Service Installed.. CONNECT!" wide ascii
		$a3 = "Done dumping SAM hashes for host:" wide ascii
		$a4 = "DA already added. Refusing to add another" wide ascii
		$a5 = "Domain info dumped into lootdir!" wide ascii

	condition:
		any of ($a*)
}

