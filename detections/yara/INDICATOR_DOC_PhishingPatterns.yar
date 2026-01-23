
rule DITEKSHEN_INDICATOR_DOC_Phishingpatterns : FILE
{
	meta:
		description = "Detects OLE, RTF, PDF and OOXML (decompressed) documents with common phishing strings"
		author = "ditekSHen"
		id = "67372eb5-ed07-5062-a12e-9ad8c7070f0f"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_office.yar#L837-L858"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "50b6566cb18512f887c07576391eb492101f7534da3460d5f7740ee6f4cf707d"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "PERFORM THE FOLLOWING STEPS TO PERFORM DECRYPTION" ascii nocase
		$s2 = "Enable Editing" ascii nocase
		$s3 = "Enable Content" ascii nocase
		$s4 = "WHY I CANNOT OPEN THIS DOCUMENT?" ascii nocase
		$s5 = "You are using iOS or Android, please use Desktop PC" ascii nocase
		$s6 = "You are trying to view this document using Online Viewer" ascii nocase
		$s7 = "This document was edited in a different version of" ascii nocase
		$s8 = "document are locked and will not" ascii nocase
		$s9 = "until the \"Enable\" button is pressed" ascii nocase
		$s10 = "This document created in online version of Microsoft Office" ascii nocase
		$s11 = "This document created in previous version of Microsoft Office" ascii nocase
		$s12 = "This document protected by Microsoft Office" ascii nocase
		$s13 = "This document encrypted by" ascii nocase
		$s14 = "document created in earlier version of microsoft office" ascii nocase

	condition:
		( uint16(0)==0xcfd0 or uint32(0)==0x74725c7b or uint32(0)==0x46445025 or uint32(0)==0x6d783f3c) and 2 of them
}
