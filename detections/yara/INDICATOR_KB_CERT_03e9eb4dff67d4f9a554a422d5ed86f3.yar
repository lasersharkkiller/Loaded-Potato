import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_03E9Eb4Dff67D4F9A554A422D5Ed86F3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "b76ab1af-01f9-5d03-8d5e-7314a7a2de43"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4270-L4281"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a56f53cb94f78496b4935fc2a613d030bd550b749427501dd9dda18cb9e05ab3"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8f2de7e770a8b1e412c2de131064d7a52da62287"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "philandro Software GmbH" and pe.signatures[i].serial=="03:e9:eb:4d:ff:67:d4:f9:a5:54:a4:22:d5:ed:86:f3")
}

