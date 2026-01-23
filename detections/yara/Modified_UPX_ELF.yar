import "elf"

rule Modified_UPX_ELF : Misc {
  meta:
    author = "@_lubiedo"
    date   = "31-08-2021"
    description = "Detect possibly modified UPX magic on ELF binaries"
  strings:
    $upx_magick = "UPX!"
    /* entries */
    $entry00 = { 50  52  E8  ??  ??  ??  ??  55  53  51  52 } // ELF64_AMD
    $entry01 = { 50 E8 }                                      // ELF_i386
    $entry02 = { 04 11 ?? ?? }                                // ELF32_MIPSEB, ELF32_MIPSEL
    $entry03 = { 18 D0 4D E2 B? }                             // ELF_ARMEL
  condition:
    filesize < 10MB and uint32be(0) == 0x7f454c46 and
    for any of ($entry*) : ( $ at elf.entry_point ) and // search for stub opcodes at entrypoint
    ( // search for UPX exec format types
      (not $upx_magick at 0xec and uint16be(filesize - 0x20) == 0x0d16) or // UPX_F_LINUX_ELF64_AMD
      (not $upx_magick at 0x98 and (uint16be(filesize - 0x20) == 0x0d17 or uint16be(filesize - 0x20) == 0x0d0c)) or // UPX_F_LINUX_ELF_i386, UPX_F_LINUX_ELF32_ARMEL
      (not $upx_magick at 0x78 and (uint16be(filesize - 0x20) == 0x0d89 or uint16be(filesize - 0x20) == 0x0d1e)) // UPX_F_LINUX_ELF32_MIPSEB, UPX_F_LINUX_ELF32_MIPSEL
    )
}

