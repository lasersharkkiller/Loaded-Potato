import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_559Cb90Fd16E9D1Ad375F050Ab6A6616 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8b2ed295-5aae-5ced-9603-8125b4e261f9"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6116-L6127"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a91f23e2281efb95b780b26018f1c89485a87c6541ac84025dad3e6dd55c742e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "78a149f9a04653b01df09743571df938f9873fa5"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Shenzhen Smartspace Software technology Co.,Limited" and pe.signatures[i].serial=="55:9c:b9:0f:d1:6e:9d:1a:d3:75:f0:50:ab:6a:66:16")
}

