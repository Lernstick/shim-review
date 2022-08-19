This repo is for review of requests for signing shim.  To create a request for review:

- clone this repo
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push that to github
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 on Linux, so asking
us to endorse anything else for signing is going to require some convincing on
your part.

Here's the template:

-------------------------------------------------------------------------------
### What organization or people are asking to have this signed?
-------------------------------------------------------------------------------
Lernstick Team (https://lernstick.ch) part of Bern University of Applied
Sciences (BFH)

-------------------------------------------------------------------------------
### What product or service is this for?
-------------------------------------------------------------------------------
* Lernstick and Lernstick Exam


-------------------------------------------------------------------------------
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
-------------------------------------------------------------------------------
Lernstick is a distribution for schools and universities for BYOD (bring your
own device) use cases and exams. It is currently mainly used in Switzerland,
Austria and Germany.

* To make BYOD work with modern devices we need the option to boot with
  SecureBoot enabled.
* For Lernstick Exam we want to implement remote attestation and need control
  over the boot chain with SecureBoot enabled on the users device.

-------------------------------------------------------------------------------
### Who is the primary contact for security updates, etc.?
The security contacts need to be verified before the shim can be accepted. For subsequent requests, contact verification is only necessary if the security contacts or their PGP keys have changed since the last successful verification.

An authorized reviewer will initiate contact verification by sending each security contact a PGP-encrypted email containing random words.
You will be asked to post the contents of these mails in your `shim-review` issue to prove ownership of the email addresses and PGP keys.

-------------------------------------------------------------------------------
- Name: Ronny Standtke
- Position: Lernstick Unit Manager
- Email address: ronny.standtke@bfh.ch
- PGP key fingerprint: E8B7F29840C34200EB6B16AEBEDD7C524A17AA3F (ronny.asc)

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

-------------------------------------------------------------------------------
### Who is the secondary contact for security updates, etc.?
-------------------------------------------------------------------------------
- Name: Roman Gruber
- Position: Main Developer for the Lernstick Exam
- Email address: p1020389@yahoo.com
- PGP key fingerprint: 3040EFCCE6703771E996FC2485A335C2114E59EC (roman.asc)

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

-------------------------------------------------------------------------------
### Were these binaries created from the 15.6 shim release tar?
Please create your shim binaries starting with the 15.6 shim release tar file: https://github.com/rhboot/shim/releases/download/15.6/shim-15.6.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.6 and contains the appropriate gnu-efi source.

-------------------------------------------------------------------------------
Yes, we are using the source from
https://github.com/rhboot/shim/releases/download/15.6/shim-15.6.tar.bz2 by using
the Debian package as the base.

-------------------------------------------------------------------------------
### URL for a repo that contains the exact code which was built to get this binary:
-------------------------------------------------------------------------------
https://github.com/lernstick/shim/tree/15.6-1-lernstick

-------------------------------------------------------------------------------
### What patches are being applied and why:
-------------------------------------------------------------------------------
No patches are applied.

-------------------------------------------------------------------------------
### If shim is loading GRUB2 bootloader what exact implementation of Secureboot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
-------------------------------------------------------------------------------
We are using the downstream GRUB2 from Debian.

-------------------------------------------------------------------------------
### If shim is loading GRUB2 bootloader and your previously released shim booted a version of grub affected by any of the CVEs in the July 2020 grub2 CVE list, the March 2021 grub2 CVE list, or the June 7th 2022 grub2 CVE list:
* CVE-2020-14372
* CVE-2020-25632
* CVE-2020-25647
* CVE-2020-27749
* CVE-2020-27779
* CVE-2021-20225
* CVE-2021-20233
* CVE-2020-10713
* CVE-2020-14308
* CVE-2020-14309
* CVE-2020-14310
* CVE-2020-14311
* CVE-2020-15705
* CVE-2021-3418 (if you are shipping the shim_lock module)

Because we are using the latest grub2 version of Debian the following CVEs are
patched: CVE-2020-14372, CVE-2020-25632, CVE-2020-25647, CVE-2020-27749,
CVE-2020-27779, CVE-2021-20225, CVE-2021-20233, CVE-2020-10713, CVE-2020-14308,
CVE-2020-14309, CVE-2020-14310, CVE-2020-14311

CVE-2020-15705 and CVE-2021-3418 do not apply to the Debian version of grub2.


* CVE-2021-3695
* CVE-2021-3696
* CVE-2021-3697
* CVE-2022-28733
* CVE-2022-28734
* CVE-2022-28735
* CVE-2022-28736

Patches for those CVEs are included in the Debian grub2 code based on 2.06. The
SBAT version was increased to allow revocation via SBAT updates.

* CVE-2022-28737

This is fixed by updating the Shim to 15.6.


### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
-------------------------------------------------------------------------------
> Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?

N/A. The first shim submission was 15.4 and GRUB2 with SBAT support.

> Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?

All the newer CVEs for grub2 will be revoked via SBAT updates.

-------------------------------------------------------------------------------
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?

-------------------------------------------------------------------------------
First two fixes are applied via the Debian patches.

The third one will be included with the latest kernel version (5.19), but has
not been backported because kgdb is not enabled for any of our kernels.

-------------------------------------------------------------------------------
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
-------------------------------------------------------------------------------
We don't use the vendor_db functionality. 


We only embed our CA certificate (`lernstick-uefi-ca.der`). This CA is used to
sign further signing certificates which are used for signing the binaries. No
other hashes are added.

We currently use the following signing certificates for signing shim, grub and
Linux files.

 * Lernstick Secure Boot 2021 - linux (fingerprint: dbbb6641a16b478b875ae997eccc2fabedee49b089cfdbf069f7dd98d3ca3dc5)
 * Lernstick Secure Boot 2021 - GRUB 2 (fingerprint: 1ab883d4b7e3fec030ae631a717665492eda0dd42f2ecc58feea84f4e6886a32)
 * Lernstick Secure Boot 2021 - shim (fingerprint: cbac3fe7790ec70c73165245db0d61812e1b454415dbcabd4e9f63f5d8237300)

-------------------------------------------------------------------------------
### If you are re-using a previously used (CA) certificate, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs to vendor_dbx in shim in order to prevent GRUB2 from being able to chainload those older GRUB2 binaries. If you are changing to a new (CA) certificate, this does not apply.
### Please describe your strategy.
-------------------------------------------------------------------------------
The previously used CA only signed GRUB2 versions with SBAT support. Loading
older vulnerable GRUB2 versions will be prevented using SBAT.

-------------------------------------------------------------------------------
### What OS and toolchain must we use to reproduce this build?  Include where to find it, etc.  We're going to try to reproduce your build as closely as possible to verify that it's really a build of the source tree you tell us it is, so these need to be fairly thorough. At the very least include the specific versions of gcc, binutils, and gnu-efi which were used, and where to find those binaries.
### If the shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case and what the differences would be.
-------------------------------------------------------------------------------
The easiest way to reproduce this build is with the supplied Dockerfile:

```
docker build . --no-cache
```

Versions of the specific packages can be found in the build log.


-------------------------------------------------------------------------------
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.

-------------------------------------------------------------------------------
`shim_15.6-1+lernstick.1_amd64.build`

-------------------------------------------------------------------------------
### What changes were made since your SHIM was last signed?
-------------------------------------------------------------------------------
The Lernstick Team moved from Bern University to Bern University of Applied
Sciences (BFH). The submission to Microsoft was already done under the BFH.

All custom Debian patches of the shim were removed by Debian upstream.

-------------------------------------------------------------------------------
### What is the SHA256 hash of your final SHIM binary?
-------------------------------------------------------------------------------
`138bcb7ebc81ac44324122b04d0e4dc6aef63d3d7fd04ddaa9d856cde1cde78e  shimx64.efi`

-------------------------------------------------------------------------------
### How do you manage and protect the keys used in your SHIM?
-------------------------------------------------------------------------------

The keys are stored on a FIPS 140-2 certified SmartCard (YubiKey FIPS Model 0010).
Only Ronny Standtke has access to this SmartCard.

-------------------------------------------------------------------------------
### Do you use EV certificates as embedded certificates in the SHIM?
-------------------------------------------------------------------------------
No.


-------------------------------------------------------------------------------
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( grub2, fwupd, fwupdate, shim + all child shim binaries )?
### Please provide exact SBAT entries for all SBAT binaries you are booting or planning to boot directly through shim.
### Where your code is only slightly modified from an upstream vendor's, please also preserve their SBAT entries to simplify revocation.
-------------------------------------------------------------------------------
grub2:

```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,2,Free Software Foundation,grub,2.06,https://www.gnu.org/software/grub/
grub.debian,1,Debian,grub2,2.06-3+lernstick.1,https://tracker.debian.org/pkg/grub2
grub.lernstick,1,Debian,grub2,2.06-3+lernstick.1,https://github.com/Lernstick/grub
```

shim:

```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,2,UEFI shim,shim,1,https://github.com/rhboot/shim
shim.debian,1,Debian,shim,15.6,https://tracker.debian.org/pkg/shim
shim.lernstick,1,Lerntsick,shim,15.6,https://github.com/Lernstick/shim
```

-------------------------------------------------------------------------------
### Which modules are built into your signed grub image?
-------------------------------------------------------------------------------
All the modules also used by Debian and `read`: 
```
all_video boot btrfs cat chain configfile cpuid cryptodisk echo efifwsetup efinet ext2 f2fs fat font gcry_arcfour gcry_blowfish gcry_camellia gcry_cast5 gcry_crc gcry_des gcry_dsa gcry_idea gcry_md4 gcry_md5 gcry_rfc2268 gcry_rijndael gcry_rmd160 gcry_rsa gcry_seed gcry_serpent gcry_sha1 gcry_sha256 gcry_sha512 gcry_tiger gcry_twofish gcry_whirlpool gettext gfxmenu gfxterm gfxterm_background gzio halt help hfsplus iso9660 jfs jpeg keystatus linux linuxefi loadenv loopback ls lsefi lsefimmap lsefisystab lssal luks lvm mdraid09 mdraid1x memdisk minicmd normal ntfs part_apple part_gpt part_msdos password_pbkdf2 play png probe raid5rec raid6rec reboot regexp search search_fs_file search_fs_uuid search_label sleep squash4 test tftp tpm true video xfs zfs zfscrypt zfsinfo read
```

-------------------------------------------------------------------------------
### What is the origin and full version number of your bootloader (GRUB or other)?
-------------------------------------------------------------------------------
Our GRUB2 is based on the 2.06-3 version from Debian which is based on the 2.06
upstream version. We do not apply any patches to the GRUB2 sources on top.

Source can be found here: https://github.com/Lernstick/grub


-------------------------------------------------------------------------------
### If your SHIM launches any other components, please provide further details on what is launched.
-------------------------------------------------------------------------------
The Shim only launches GRUB2.

-------------------------------------------------------------------------------
### If your GRUB2 launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
-------------------------------------------------------------------------------
We only launch the Linux kernel.

-------------------------------------------------------------------------------
### How do the launched components prevent execution of unauthenticated code?
-------------------------------------------------------------------------------

* Signed Linux images have Lockdown via Debian's patches enabled.
* GRUB2 has Secure Boot patches applied and only launches our signed files.


-------------------------------------------------------------------------------
### Does your SHIM load any loaders that support loading unsigned kernels (e.g. GRUB)?
-------------------------------------------------------------------------------
No.

-------------------------------------------------------------------------------
### What kernel are you using? Which patches does it includes to enforce Secure Boot?
-------------------------------------------------------------------------------
We are using 5.18 which Lockdown patches from Debian.

-------------------------------------------------------------------------------
### Add any additional information you think we may need to validate this shim.
-------------------------------------------------------------------------------
The email address of Ronny Standtke changed to ronny.standtke@bfh.ch. The PGP
key is the same.

Last accepted submission is: https://github.com/rhboot/shim-review/issues/196
