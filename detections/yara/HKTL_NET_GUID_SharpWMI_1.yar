import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpwmi_1 : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "cd5a1c7b-a45a-5541-b1b0-cf19c991ed22"
		date = "2020-12-28"
		modified = "2023-04-06"
		old_rule_name = "HKTL_NET_GUID_sharpwmi"
		reference = "https://github.com/QAX-A-Team/sharpwmi"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3181-L3196"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "85e22c021c6d421e97d7ea811b3d3800c487a0185ddab6cb80b2d35cb97a73d7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "bb357d38-6dc1-4f20-a54c-d664bd20677e" ascii wide
		$typelibguid0up = "BB357D38-6DC1-4F20-A54C-D664BD20677E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
