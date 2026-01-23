import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Ca41D2D9F5E991F49B162D584B0F386 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "bd395177-daf6-56b1-822c-e659083e0f53"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L536-L547"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "51f80dfd63b273e62abaa8b60a00525cfdc6b28341466a9f414703382ad088bd"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "23250aa8e1b8ae49a64d09644db3a9a65f866957"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VB CORPORATE PTY. LTD." and pe.signatures[i].serial=="0c:a4:1d:2d:9f:5e:99:1f:49:b1:62:d5:84:b0:f3:86")
}

