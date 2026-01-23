
rule VOLEXITY_Cf_Office_Win_Macro_Lazarus_Jeus : LAZARUS
{
	meta:
		description = "Detects malicious documents used by Lazarus in a campaign dropping the AppleJeus malware."
		author = "threatintel@volexity.com"
		id = "03d41314-c19f-566f-9571-48915a292433"
		date = "2022-11-02"
		modified = "2022-12-01"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L106-L124"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "8e5a9042ec1ddaf4da511743434461c9865f259c30a9b02c28475b3a59fe4fc1"
		score = 75
		quality = 80
		tags = "LAZARUS"
		hash1 = "17e6189c19dedea678969e042c64de2a51dd9fba69ff521571d63fd92e48601b"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s1 = "0M8R4K" ascii
		$s2 = "bin.base64" ascii
		$s3 = "dragon" ascii
		$s4 = "Workbook_Open" ascii

	condition:
		3 of ($s*)
}
