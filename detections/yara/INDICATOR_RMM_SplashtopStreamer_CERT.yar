import "pe"


rule DITEKSHEN_INDICATOR_RMM_Splashtopstreamer_CERT : FILE
{
	meta:
		description = "Detects Splashtop Streamer by certificate. Review RMM Inventory"
		author = "ditekSHen"
		id = "7e0e4d6f-38a3-5cac-8a82-8aea7943d373"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L405-L419"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "0a1225a79ff30678846b9cb4315419be04b46276b3e05310a21d088b30f01b72"
		score = 75
		quality = 75
		tags = "FILE"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].issuer contains "DigiCert" and pe.signatures[i].subject contains "Splashtop Inc.")
}
