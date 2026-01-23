import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Vaultschemaguid : FILE
{
	meta:
		description = "Detects executables referencing Windows vault credential objects. Observed in infostealers"
		author = "ditekSHen"
		id = "440ac8a8-19c9-5284-a8e2-e0f2e8892a5e"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1928-L1951"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "121a51bbb749cc86d50fd5f79d7a24fbbb3e589e2fb25c553764a16202ff4065"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "2F1A6504-0641-44CF-8BB5-3612D865F2E5" ascii wide
		$s2 = "3CCD5499-87A8-4B10-A215-608888DD3B55" ascii wide
		$s3 = "154E23D0-C644-4E6F-8CE6-5069272F999F" ascii wide
		$s4 = "4BF4C442-9B8A-41A0-B380-DD4A704DDB28" ascii wide
		$s5 = "77BC582B-F0A6-4E15-4E80-61736B6F3B29" ascii wide
		$s6 = "E69D7838-91B5-4FC9-89D5-230D4D4CC2BC" ascii wide
		$s7 = "3E0E35BE-1B77-43E7-B873-AED901B6275B" ascii wide
		$s8 = "3C886FF3-2669-4AA2-A8FB-3F6759A77548" ascii wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}

