rule nbtscan_utility_softcell {

   meta:

      description = "Rule to detect nbtscan utility used in the SoftCell operation"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-06-25"
      rule_version = "v1"
      malware_type = "utility"
      malware_family = "Utility:W32/NbtScan"
      actor_type = "Apt"
      actor_group = "Unknown"
      reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"

   strings:

      $s1 = "nbtscan 1.0.35 - 2008-04-08 - http://www.unixwiz.net/tools/" fullword ascii
      $s2 = "parse_target_cb.c" fullword ascii
      $s3 = "ranges. Ranges can be in /nbits notation (\"192.168.12.0/24\")" fullword ascii
      $s4 = "or with a range in the last octet (\"192.168.12.64-97\")" fullword ascii

      $op0 = { 52 68 d4 66 40 00 8b 85 58 ff ff ff 50 ff 15 a0 }
      $op1 = { e9 1c ff ff ff 8b 45 fc 8b e5 5d c3 cc cc cc cc }
      $op2 = { 59 59 c3 8b 65 e8 ff 75 d0 ff 15 34 60 40 00 ff }

   condition:

      uint16(0) == 0x5a4d and
      filesize < 100KB and
      ( pe.imphash() == "2fa43c5392ec7923ababced078c2f98d" and
      all of them )
}

