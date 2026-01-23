rule BINARYALERT_Hacktool_Windows_Mimikatz_Files
{
	meta:
		description = "Mimikatz credential dump tool: Files"
		author = "@fusionrace"
		id = "ea4fd443-64dd-5466-8525-40c3a023e229"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://github.com/gentilkiwi/mimikatz"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/windows/hacktool_windows_mimikatz_files.yara#L1-L15"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "50d23cda49ca559da2e504e53b46b58679ea8bc07c501ff7764a3d142598adc8"
		score = 75
		quality = 80
		tags = ""
		md5_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
		md5_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"

	strings:
		$s1 = "kiwifilter.log" fullword wide
		$s2 = "kiwissp.log" fullword wide
		$s3 = "mimilib.dll" fullword ascii wide

	condition:
		any of them
}

