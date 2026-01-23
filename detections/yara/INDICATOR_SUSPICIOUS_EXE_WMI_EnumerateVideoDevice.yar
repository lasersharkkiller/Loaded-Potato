import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_WMI_Enumeratevideodevice : FILE
{
	meta:
		description = "Detects executables attemping to enumerate video devices using WMI"
		author = "ditekSHen"
		id = "6d4ede5e-4ec5-5753-bd50-8e129ac532a4"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1486-L1500"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "8ef63d7a569ee1530a23d151ee394969f4b3b6bac28ed571f48e3f97b87d020a"
		score = 40
		quality = 41
		tags = "FILE"
		importance = 20

	strings:
		$q1 = "Select * from Win32_CacheMemory" ascii wide nocase
		$d1 = "{860BB310-5D01-11d0-BD3B-00A0C911CE86}" ascii wide
		$d2 = "{62BE5D10-60EB-11d0-BD3B-00A0C911CE86}" ascii wide
		$d3 = "{55272A00-42CB-11CE-8135-00AA004BB851}" ascii wide
		$d4 = "SYSTEM\\ControlSet001\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\000" ascii wide nocase
		$d5 = "HardwareInformation.AdapterString" ascii wide
		$d6 = "HardwareInformation.qwMemorySize" ascii wide

	condition:
		uint16(0)==0x5a4d and ((1 of ($q*) and 1 of ($d*)) or 3 of ($d*))
}

