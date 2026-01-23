rule BINARYALERT_Hacktool_Windows_Mimikatz_Sekurlsa
{
	meta:
		description = "Mimikatz credential dump tool"
		author = "@fusionrace"
		id = "08fe62c5-f7a4-5985-a298-1d3c2c1744d4"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://github.com/gentilkiwi/mimikatz"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/windows/hacktool_windows_mimikatz_sekurlsa.yara#L1-L18"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "24e958c3cbda8e01dc2d84b3059114ea23f4b38db1676f7b72e5eabfa52b7335"
		score = 75
		quality = 80
		tags = ""
		SHA256_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
		SHA256_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"

	strings:
		$s1 = "dpapisrv!g_MasterKeyCacheList" fullword ascii wide
		$s2 = "lsasrv!g_MasterKeyCacheList" fullword ascii wide
		$s3 = "!SspCredentialList" ascii wide
		$s4 = "livessp!LiveGlobalLogonSessionList" fullword ascii wide
		$s5 = "wdigest!l_LogSessList" fullword ascii wide
		$s6 = "tspkg!TSGlobalCredTable" fullword ascii wide

	condition:
		all of them
}

