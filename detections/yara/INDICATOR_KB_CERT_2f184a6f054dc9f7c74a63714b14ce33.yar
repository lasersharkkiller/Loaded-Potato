import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2F184A6F054Dc9F7C74A63714B14Ce33 : FILE
{
	meta:
		description = "Detects executables signed AprelTech Silent Install Builder certificate"
		author = "ditekSHen"
		id = "17797e5c-acf2-5c4e-b3e0-c48fb7bff996"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3043-L3054"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "d14428b81b4ae4a77a517d2148f4b67b45963b71d998139b42ed4e4352fae6a5"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ec9c6a537f6d7a0e63a4eb6aeb0df9d5b466cc58"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "APREL Tehnologija d.o.o." and pe.signatures[i].serial=="2f:18:4a:6f:05:4d:c9:f7:c7:4a:63:71:4b:14:ce:33")
}

