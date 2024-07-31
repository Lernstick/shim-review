This repo is for review of requests for signing shim. To create a request for review:

- clone this repo (preferably fork it)
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push it to GitHub
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 or systemd-boot on Linux, so
asking us to endorse anything else for signing is going to require some convincing on
your part.

Hint: check the [docs](./docs/) directory in this repo for guidance on submission and getting your shim signed.

Here's the template:

### What organization or people are asking to have this signed?
*******************************************************************************
Lernstick Team (https://lernstick.ch) part of Bern University of Applied
Sciences (BFH)

*******************************************************************************
### What product or service is this for?
*******************************************************************************
* Lernstick and Lernstick Exam

*******************************************************************************
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
*******************************************************************************
Lernstick is a distribution for schools and universities for BYOD (bring your
own device) use cases and exams. It is currently mainly used in Switzerland,
Austria and Germany.

* To make BYOD work with modern devices we need the option to boot with
  SecureBoot enabled.
* For Lernstick Exam we want to implement remote attestation and need control
  over the boot chain with SecureBoot enabled on the users device.

*******************************************************************************
### Why are you unable to reuse shim from another distro that is already signed?
*******************************************************************************
We build custom kernels with additional hardware support and custom options.

*******************************************************************************
### Who is the primary contact for security updates, etc.?
The security contacts need to be verified before the shim can be accepted. For subsequent requests, contact verification is only necessary if the security contacts or their PGP keys have changed since the last successful verification.

An authorized reviewer will initiate contact verification by sending each security contact a PGP-encrypted email containing random words.
You will be asked to post the contents of these mails in your `shim-review` issue to prove ownership of the email addresses and PGP keys.
*******************************************************************************
- Name: Ronny Standtke
- Position: Lernstick Unit Manager
- Email address: ronny.standtke@bfh.ch
- PGP key fingerprint: E8B7F29840C34200EB6B16AEBEDD7C524A17AA3F (ronny.asc)

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************
### Who is the secondary contact for security updates, etc.?
*******************************************************************************
- Name: Jörg Berkel
- Position: Lernstick Developer
- Email address: joerg.berkel@bfh.ch
- PGP key fingerprint: F5B1FA7FE22CE188B2D97B40CB893BFB8992CDFE (jörg.asc)

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************
### Were these binaries created from the 15.8 shim release tar?
Please create your shim binaries starting with the 15.8 shim release tar file: https://github.com/rhboot/shim/releases/download/15.8/shim-15.8.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.8 and contains the appropriate gnu-efi source.

Make sure the tarball is correct by verifying your download's checksum with the following ones:

```
a9452c2e6fafe4e1b87ab2e1cac9ec00  shim-15.8.tar.bz2
cdec924ca437a4509dcb178396996ddf92c11183  shim-15.8.tar.bz2
a79f0a9b89f3681ab384865b1a46ab3f79d88b11b4ca59aa040ab03fffae80a9  shim-15.8.tar.bz2
30b3390ae935121ea6fe728d8f59d37ded7b918ad81bea06e213464298b4bdabbca881b30817965bd397facc596db1ad0b8462a84c87896ce6c1204b19371cd1  shim-15.8.tar.bz2
```

Make sure that you've verified that your build process uses that file as a source of truth (excluding external patches) and its checksum matches. Furthermore, there's [a detached signature as well](https://github.com/rhboot/shim/releases/download/15.8/shim-15.8.tar.bz2.asc) - check with the public key that has the fingerprint `8107B101A432AAC9FE8E547CA348D61BC2713E9F` that the tarball is authentic. Once you're sure, please confirm this here with a simple *yes*.

A short guide on verifying public keys and signatures should be available in the [docs](./docs/) directory.
*******************************************************************************
Yes. We are using the Debian package as the base.

*******************************************************************************
### URL for a repo that contains the exact code which was built to result in your binary:
Hint: If you attach all the patches and modifications that are being used to your application, you can point to the URL of your application here (*`https://github.com/YOUR_ORGANIZATION/shim-review`*).

You can also point to your custom git servers, where the code is hosted.
*******************************************************************************

https://github.com/Lernstick/shim/tree/lernstick_15.8-1-lernstick


*******************************************************************************
### What patches are being applied and why:
Mention all the external patches and build process modifications, which are used during your building process, that make your shim binary be the exact one that you posted as part of this application.
*******************************************************************************
We include the same patches as Debian. See `debian/patches` in the shim repo:

- `0001-sbat-Add-grub.peimage-2-to-latest-CVE-2024-2312.patch` Patch straight from upstream to add a SBAT revocation for grub.peimage

- `0002-sbat-Also-bump-latest-for-grub-4-and-to-todays-date.patch` Patch straight from upstream to bump SBAT for grub

In our shim build, we set SBAT_AUTOMATIC_DATE=2023012900 to revoke older grub builds by default, which differs to Debian's setting which is set to 2024010900.


*******************************************************************************
### Do you have the NX bit set in your shim? If so, is your entire boot stack NX-compatible and what testing have you done to ensure such compatibility?

See https://techcommunity.microsoft.com/t5/hardware-dev-center/nx-exception-for-shim-community/ba-p/3976522 for more details on the signing of shim without NX bit.
*******************************************************************************
The NX bit is not set.

*******************************************************************************
### What exact implementation of Secure Boot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
Skip this, if you're not using GRUB2.
*******************************************************************************
We are using the downstream GRUB2 from Debian.

*******************************************************************************
### Do you have fixes for all the following GRUB2 CVEs applied?
**Skip this, if you're not using GRUB2, otherwise make sure these are present and confirm with _yes_.**

* 2020 July - BootHole
  * Details: https://lists.gnu.org/archive/html/grub-devel/2020-07/msg00034.html
  * CVE-2020-10713
  * CVE-2020-14308
  * CVE-2020-14309
  * CVE-2020-14310
  * CVE-2020-14311
  * CVE-2020-15705
  * CVE-2020-15706
  * CVE-2020-15707
* March 2021
  * Details: https://lists.gnu.org/archive/html/grub-devel/2021-03/msg00007.html
  * CVE-2020-14372
  * CVE-2020-25632
  * CVE-2020-25647
  * CVE-2020-27749
  * CVE-2020-27779
  * CVE-2021-3418 (if you are shipping the shim_lock module)
  * CVE-2021-20225
  * CVE-2021-20233
* June 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-06/msg00035.html, SBAT increase to 2
  * CVE-2021-3695
  * CVE-2021-3696
  * CVE-2021-3697
  * CVE-2022-28733
  * CVE-2022-28734
  * CVE-2022-28735
  * CVE-2022-28736
  * CVE-2022-28737
* November 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-11/msg00059.html, SBAT increase to 3
  * CVE-2022-2601
  * CVE-2022-3775
* October 2023 - NTFS vulnerabilities
  * Details: https://lists.gnu.org/archive/html/grub-devel/2023-10/msg00028.html, SBAT increase to 4
  * CVE-2023-4693
  * CVE-2023-4692
*******************************************************************************

Yes all those are patched. CVE-2020-15705 did not affect the Debian version of GRUB2.

*******************************************************************************
### If shim is loading GRUB2 bootloader, and if these fixes have been applied, is the upstream global SBAT generation in your GRUB2 binary set to 4?
Skip this, if you're not using GRUB2, otherwise do you have an entry in your GRUB2 binary similar to:  
`grub,4,Free Software Foundation,grub,GRUB_UPSTREAM_VERSION,https://www.gnu.org/software/grub/`?
*******************************************************************************

Yes.

*******************************************************************************
### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
If you had no previous signed shim, say so here. Otherwise a simple _yes_ will do.
*******************************************************************************

> Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?

N/A. The first shim submission was 15.4 and GRUB2 with SBAT support.

> Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?

All the newer CVEs for GRUB2 will be revoked via SBAT updates.

*******************************************************************************
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?
Hint: upstream kernels should have all these applied, but if you ship your own heavily-modified older kernel version, that is being maintained separately from upstream, this may not be the case.  
If you are shipping an older kernel, double-check your sources; maybe you do not have all the patches, but ship a configuration, that does not expose the issue(s).
*******************************************************************************
The 6.6 and 6.7 kernel include all those patches and kgdb is not enabled in any of our kernels.

*******************************************************************************
### Do you build your signed kernel with additional local patches? What do they do?
*******************************************************************************

We include patches for T2 Apple and Surface devices devices:
- https://github.com/t2linux/linux-t2-patches
- https://github.com/linux-surface/linux-surface

Further we sign the following thrid-party modules:
- nvidia
- broadcom-sta
- virtualbox
- v4l2loopback

See here for more discussion: https://github.com/rhboot/shim-review/issues/292

Kernel packaging can be found here: https://github.com/Lernstick/linux

*******************************************************************************
### Do you use an ephemeral key for signing kernel modules?
### If not, please describe how you ensure that one kernel build does not load modules built for another kernel.
*******************************************************************************

Partly. We use an ephemeral key for the builtin kernel modules.
For the third-party kernel modules we include a kernel package version specific key that is secured in an HSM.


*******************************************************************************
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
*******************************************************************************

We do not use the `vendor_db` functionality.

*******************************************************************************
### If you are re-using the CA certificate from your last shim binary, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs mentioned earlier to vendor_dbx in shim. Please describe your strategy.
This ensures that your new shim+GRUB2 can no longer chainload those older GRUB2 binaries with issues.

If this is your first application or you're using a new CA certificate, please say so here.
*******************************************************************************

The previously used CA only signed GRUB2 versions with SBAT support. Loading
older vulnerable GRUB2 versions will be prevented using SBAT.


*******************************************************************************
### Is the Dockerfile in your repository the recipe for reproducing the building of your shim binary?
A reviewer should always be able to run `docker build .` to get the exact binary you attached in your application.

Hint: Prefer using *frozen* packages for your toolchain, since an update to GCC, binutils, gnu-efi may result in building a shim binary with a different checksum.

If your shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case, what the differences would be and what build environment (OS and toolchain) is being used to reproduce this build? In this case please write a detailed guide, how to setup this build environment from scratch.
*******************************************************************************

The easiest way to reproduce this build is with the supplied Dockerfile:

```
docker build . --no-cache
```

Versions of the specific packages can be found in the build log.

*******************************************************************************
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
*******************************************************************************

`shim_15.8-1+lernstick.2_amd64.build`

*******************************************************************************
### What changes were made in the distro's secure boot chain since your SHIM was last signed?
For example, signing new kernel's variants, UKI, systemd-boot, new certs, new CA, etc..

Skip this, if this is your first application for having shim signed.
*******************************************************************************

* We switched to newer grub release + peimage patches
* We use ephemeral keysigning for builtin modules and use a kernel package version specific one for third-party modules.
* We rotated our signing certificates for Kernel and GRUB to new ones
  * Allows us to revoke old kernels easily in the future with the old signing scheme
* We move from Shim 15.7 to 15.8 including revocations for older GRUB2 versions.


*******************************************************************************
### What is the SHA256 hash of your final shim binary?
*******************************************************************************

```
6544e9cee3a3308c9090875a8edb40be648b222db7c17f09ab4801c5b4ef5268  shimx64.efi
```

*******************************************************************************
### How do you manage and protect the keys used in your shim?
Describe the security strategy that is used for key protection. This can range from using hardware tokens like HSMs or Smartcards, air-gapped vaults, physical safes to other good practices.
*******************************************************************************

The keys are stored on a FIPS 140-2 certified SmartCard (YubiKey FIPS Model 0010).
Only Ronny Standtke has access to this SmartCard.

*******************************************************************************
### Do you use EV certificates as embedded certificates in the shim?
A _yes_ or _no_ will do. There's no penalty for the latter.
*******************************************************************************

No.

*******************************************************************************
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( GRUB2, fwupd, fwupdate, systemd-boot, systemd-stub, shim + all child shim binaries )?
### Please provide the exact SBAT entries for all binaries you are booting directly through shim.
Hint: The history of SBAT and more information on how it works can be found [here](https://github.com/rhboot/shim/blob/main/SBAT.md). That document is large, so for just some examples check out [SBAT.example.md](https://github.com/rhboot/shim/blob/main/SBAT.example.md)

If you are using a downstream implementation of GRUB2 (e.g. from Fedora or Debian), make sure you have their SBAT entries preserved and that you **append** your own (don't replace theirs) to simplify revocation.

**Remember to post the entries of all the binaries. Apart from your bootloader, you may also be shipping e.g. a firmware updater, which will also have these.**

Hint: run `objcopy --only-section .sbat -O binary YOUR_EFI_BINARY /dev/stdout` to get these entries. Paste them here. Preferably surround each listing with three backticks (\`\`\`), so they render well.
*******************************************************************************
Shim:

```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,4,UEFI shim,shim,1,https://github.com/rhboot/shim
shim.lernstick,1,Lerntsick,shim,15.8,https://github.com/Lernstick/shim
```

GRUB2:
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,4,Free Software Foundation,grub,2.12,https://www.gnu.org/software/grub/
grub.debian,5,Debian,grub2,2.12-2+lernstick.1,https://tracker.debian.org/pkg/grub2
grub.debian13,1,Debian,grub2,2.12-2+lernstick.1,https://tracker.debian.org/pkg/grub2
grub.lernstick,1,Debian,grub2,2.12-2+lernstick.1,https://github.com/Lernstick/grub
grub.peimage,2,Canonical,grub2,2.12-2+lernstick.1,https://salsa.debian.org/grub-team/grub/-/blob/master/debian/patches/secure-boot/efi-use-peimage-shim.patch
```


*******************************************************************************
### If shim is loading GRUB2 bootloader, which modules are built into your signed GRUB2 image?
Skip this, if you're not using GRUB2.

Hint: this is about those modules that are in the binary itself, not the `.mod` files in your filesystem.
*******************************************************************************
Same as Debian + `read` module:
```
all_video boot btrfs cat chain configfile cpuid cryptodisk echo
efifwsetup efinet ext2 f2fs fat fdt font gcry_arcfour gcry_blowfish
gcry_camellia gcry_cast5 gcry_crc gcry_des gcry_dsa gcry_idea gcry_md4
gcry_md5 gcry_rfc2268 gcry_rijndael gcry_rmd160 gcry_rsa gcry_seed
gcry_serpent gcry_sha1 gcry_sha256 gcry_sha512 gcry_tiger gcry_twofish
gcry_whirlpool gettext gfxmenu gfxterm gfxterm_background gzio
halt help hfsplus http iso9660 jfs jpeg keystatus linux loadenv
loopback ls lsefi lsefimmap lsefisystab lssal luks luks2 lvm mdraid09
mdraid1x memdisk minicmd normal ntfs part_apple part_gpt part_msdos
password_pbkdf2 peimage play png probe raid5rec raid6rec reboot regexp
search search_fs_file search_fs_uuid search_label serial sleep smbios
squash4 test tftp tpm true video xfs zfs zfscrypt zfsinfo read
```

See also: https://github.com/Lernstick/grub/blob/lernstick/2.12/debian/build-efi-images

*******************************************************************************
### If you are using systemd-boot on arm64 or riscv, is the fix for [unverified Devicetree Blob loading](https://github.com/systemd/systemd/security/advisories/GHSA-6m6p-rjcq-334c) included?
*******************************************************************************
N/A. Not using systemd-boot.

*******************************************************************************
### What is the origin and full version number of your bootloader (GRUB2 or systemd-boot or other)?
*******************************************************************************
The latest version we use is `2.12-2+lernstick.1` based on Debians `2.12-2~deb13u1`.

Source can be found here: https://github.com/Lernstick/grub/tree/lernstick/2.12


*******************************************************************************
### If your shim launches any other components apart from your bootloader, please provide further details on what is launched.
Hint: The most common case here will be a firmware updater like fwupd.
*******************************************************************************

We only launch GRUB2 and the Linux kernel.

*******************************************************************************
### If your GRUB2 or systemd-boot launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
Skip this, if you're not using GRUB2 or systemd-boot.
*******************************************************************************

N/A.

*******************************************************************************
### How do the launched components prevent execution of unauthenticated code?
Summarize in one or two sentences, how your secure bootchain works on higher level.
*******************************************************************************

* Signed Linux images have lockdown via Debian's patches enabled.
* GRUB2 is Secure Boot aware and only launches our signed files when booted in Secure Boot mode.


*******************************************************************************
### Does your shim load any loaders that support loading unsigned kernels (e.g. certain GRUB2 configurations)?
*******************************************************************************

No. The Shim only launches GRUB2 which only launches signed kernels in Secure Boot.

*******************************************************************************
### What kernel are you using? Which patches and configuration does it include to enforce Secure Boot?
*******************************************************************************
We are tracking the Debian bookworm-backports.
Version used in the current release 6.6.13, next one is 6.7.12.

We include the Debian lockdown patches.

*******************************************************************************
### What contributions have you made to help us review the applications of other applicants?
The reviewing process is meant to be a peer-review effort and the best way to have your application reviewed faster is to help with reviewing others. We are in most cases volunteers working on this venue in our free time, rather than being employed and paid to review the applications during our business hours. 

A reasonable timeframe of waiting for a review can reach 2-3 months. Helping us is the best way to shorten this period. The more help we get, the faster and the smoother things will go.

For newcomers, the applications labeled as [*easy to review*](https://github.com/rhboot/shim-review/issues?q=is%3Aopen+is%3Aissue+label%3A%22easy+to+review%22) are recommended to start the contribution process.
*******************************************************************************

@THS-on is part of the team and has been reviewing Shims for a longer time now. 

*******************************************************************************
### Add any additional information you think we may need to validate this shim signing application.
*******************************************************************************

* Second security contact has changed to Jörg Berkel
* We dropped the Debian SBAT entry from the Shim, as there are no longer a lot out-of-tree patches (besides the revocations)
* At the moment we are not planning on providing UKIs, signing fwupd or systemd-boot
