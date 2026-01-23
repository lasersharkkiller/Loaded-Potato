import "pe"


rule DITEKSHEN_INDICATOR_RMM_Connectwise_Screenconnect_CERT : FILE
{
	meta:
		description = "Detects ConnectWise Control (formerly ScreenConnect) by (default) certificate. Review RMM Inventory"
		author = "ditekSHen"
		id = "7a032c24-8a9e-51c3-983e-62e13594aa35"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L85-L99"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "14291bd9ddb7fd3ee7932f8104687aae58fe7f5de13726153e5e1ee9c211f598"
		score = 75
		quality = 75
		tags = "FILE"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].issuer contains "DigiCert" and pe.signatures[i].subject contains "Connectwise, LLC")
}
