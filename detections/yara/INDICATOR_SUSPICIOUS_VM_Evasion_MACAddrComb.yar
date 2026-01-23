import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_VM_Evasion_Macaddrcomb : FILE
{
	meta:
		description = "Detects executables referencing virtualization MAC addresses"
		author = "ditekSHen"
		id = "7e399d31-090a-57f7-89fa-0a2c4e563283"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1810-L1825"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "53a87bffc327c38545d9f213834726af9a1fbe86f273e189dc355567e6a671bf"
		score = 40
		quality = 29
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "00:03:FF" ascii wide nocase
		$s2 = "00:05:69" ascii wide nocase
		$s3 = "00:0C:29" ascii wide nocase
		$s4 = "00:16:3E" ascii wide nocase
		$s5 = "00:1C:14" ascii wide nocase
		$s6 = "00:1C:42" ascii wide nocase
		$s7 = "00:50:56" ascii wide nocase
		$s8 = "08:00:27" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 3 of them
}

