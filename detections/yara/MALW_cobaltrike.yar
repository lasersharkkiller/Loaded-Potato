
rule TRELLIX_ARC_MALW_Cobaltrike : BACKDOOR FILE
{
	meta:
		description = "Rule to detect CobaltStrike beacon"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a7dae4c7-672e-58fb-8542-90fa90d991a4"
		date = "2020-07-19"
		modified = "2021-08-30"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_cobaltstrike.yar#L1-L38"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "fc91d40c6544c7ab7c60b3cb8fc542bd4a6fac79dbe00cad8f612854f2a6dcd1"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/CobaltStrike"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		hash1 = "f47a627880bfa4a117fec8be74ab206690e5eb0e9050331292e032cd22883f5b"

	strings:
		$pattern_0 = { e9???????? eb0a b801000000 e9???????? }
		$pattern_1 = { 3bc7 750d ff15???????? 3d33270000 }
		$pattern_2 = { 8bd0 e8???????? 85c0 7e0e }
		$pattern_3 = { 50 8d8d24efffff 51 e8???????? }
		$pattern_4 = { 03b5d4eeffff 89b5c8eeffff 3bf7 72bd 3bf7 }
		$pattern_5 = { 8b450c 8945f4 8d45f4 50 }
		$pattern_6 = { 33c5 8945fc 8b4508 53 56 ff750c 33db }
		$pattern_7 = { e8???????? e9???????? 833d????????01 7505 e8???????? }
		$pattern_8 = { 53 53 8d85f4faffff 50 }
		$pattern_9 = { 68???????? 53 50 e8???????? 83c424 }
		$pattern_10 = { 488b4c2420 8b0401 8b4c2408 33c8 8bc1 89442408 }
		$pattern_11 = { 488d4d97 e8???????? 4c8d9c24d0000000 418bc7 498b5b20 498b7328 498b7b30 }
		$pattern_12 = { bd08000000 85d2 7459 ffcf 4d85ed }
		$pattern_13 = { 4183c9ff 33d2 ff15???????? 4c63c0 4983f8ff }
		$pattern_14 = { 49c1e002 e8???????? 03f3 4d8d349e 3bf5 7d13 }
		$pattern_15 = { 752c 4c8d45af 488d55af 488d4d27 }

	condition:
		7 of them and filesize <696320
}
