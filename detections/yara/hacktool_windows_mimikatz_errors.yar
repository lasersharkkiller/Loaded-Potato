rule BINARYALERT_Hacktool_Windows_Mimikatz_Errors
{
	meta:
		description = "Mimikatz credential dump tool: Error messages"
		author = "@fusionrace"
		id = "94d50739-fc84-5bfe-821d-5e2851f681e3"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://github.com/gentilkiwi/mimikatz"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/windows/hacktool_windows_mimikatz_errors.yara#L1-L16"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "60fb94b9465b19af3b2df1b26490d4ac19a31a39f2f8c52f1059d37843769b36"
		score = 75
		quality = 80
		tags = ""
		md5_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
		md5_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"

	strings:
		$s1 = "[ERROR] [LSA] Symbols" fullword ascii wide
		$s2 = "[ERROR] [CRYPTO] Acquire keys" fullword ascii wide
		$s3 = "[ERROR] [CRYPTO] Symbols" fullword ascii wide
		$s4 = "[ERROR] [CRYPTO] Init" fullword ascii wide

	condition:
		all of them
}

