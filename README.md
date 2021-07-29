This repo is for review of requests for signing shim.  To create a request for review:

- clone this repo
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push that to github
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your branch
- approval is ready when you have accepted tag

Note that we really only have experience with using GRUB2 on Linux, so asking
us to endorse anything else for signing is going to require some convincing on
your part.

Here's the template:

-------------------------------------------------------------------------------
What organization or people are asking to have this signed:
-------------------------------------------------------------------------------
Lernstick Team part of the Research Center for Digital Sustainability at
University of Bern (https://lernstick.ch)

-------------------------------------------------------------------------------
What product or service is this for:
-------------------------------------------------------------------------------
* Lernstick and Lernstick Exam

-------------------------------------------------------------------------------
What's the justification that this really does need to be signed for the whole world to be able to boot it:
-------------------------------------------------------------------------------
Lernstick is a distribution for schools and universities for BYOD (bring your
own device) use cases and exams. It is currently mainly used in Switzerland,
Austria and Germany.

* To make BYOD work with modern devices we need the option to boot with
  SecureBoot enabled.
* For Lernstick Exam we want to implement remote attestation and need control
  over the boot chain with SecureBoot enabled on the users device.


-------------------------------------------------------------------------------
Who is the primary contact for security updates, etc.
-------------------------------------------------------------------------------
- Name: Ronny Standtke
- Position: Lernstick Unit Manager
- Email address: ronny.standtke@inf.unibe.ch
- PGP key, signed by the other security contacts, and preferably also with signatures that are reasonably well known in the Linux community:
	- see file ronny.asc

-------------------------------------------------------------------------------
Who is the secondary contact for security updates, etc.
-------------------------------------------------------------------------------
- Name: Roman Gruber
- Position: Main Developer for the Lernstick Exam
- Email address: p1020389@yahoo.com
- PGP key, signed by the other security contacts, and preferably also with signatures that are reasonably well known in the Linux community:
	- see file roman.asc

-------------------------------------------------------------------------------
Please create your shim binaries starting with the 15.4 shim release tar file:
https://github.com/rhboot/shim/releases/download/15.4/shim-15.4.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.4 and contains
the appropriate gnu-efi source.
-------------------------------------------------------------------------------
We confirm that we are using the source from
https://github.com/rhboot/shim/releases/download/15.4/shim-15.4.tar.bz2.


-------------------------------------------------------------------------------
URL for a repo that contains the exact code which was built to get this binary:
-------------------------------------------------------------------------------
https://github.com/Lernstick/shim/releases/tag/15.4-6-lernstick

-------------------------------------------------------------------------------
What patches are being applied and why:
-------------------------------------------------------------------------------
We are tracking the Debian Shim package and therefore including the same patches
for 15.04 as recommended. Those are included in the `debian/patches` folder.

* fix-import_one_mok_state.patch issue #362 (Fix mokutil --disable-validation) upstream commit 822d07ad4f07ef66fe447a130e1027c88d02a394

* fix-broken-ia32-reloc.patch issue #357 (Fix a broken file header on ia32) upstream commit 1bea91ba72165d97c3b453cf769cb4bc5c07207a

* MOK-BootServicesData.patch issue #361 (mok: allocate MOK config table as BootServicesData) upstream commit 4068fd42c891ea6ebdec056f461babc6e4048844

* Don-t-call-QueryVariableInfo-on-EFI-1.10-machines.patch issue #364 (fails to boot on older Macs, and other machines with EFI < 2) upstream commit 493bd940e5c6e28e673034687de7adef9529efff

* relax_check_for_import_mok_state.patch issue #372 (Relax the check for import_mok_state()) upstream commit 9f973e4e95b1136b8c98051dbbdb1773072cc998

* fix_arm64_rela_sections.patch issue #371 (arm/aa64: fix the size of .rela* sections) commit 9828f65f3e9de29da7bc70cb71069cc1d7ca1b4a in the PR from Gary Lin


-------------------------------------------------------------------------------
If bootloader, shim loading is, GRUB2: is CVE-2020-14372, CVE-2020-25632,
 CVE-2020-25647, CVE-2020-27749, CVE-2020-27779, CVE-2021-20225, CVE-2021-20233,
 CVE-2020-10713, CVE-2020-14308, CVE-2020-14309, CVE-2020-14310, CVE-2020-14311,
 CVE-2020-15705, and if you are shipping the shim_lock module CVE-2021-3418
-------------------------------------------------------------------------------
Yes, those CVEs are fixed in the GRUB2 version from Debian we are using.


-------------------------------------------------------------------------------
What exact implementation of Secureboot in GRUB2 ( if this is your bootloader ) you have ?
* Upstream GRUB2 shim_lock verifier or 
* Downstream RHEL/Fedora/Debian/Canonical like implementation ?
-------------------------------------------------------------------------------
We are using the downstream GRUB2 from Debian.

-------------------------------------------------------------------------------
If bootloader, shim loading is, GRUB2, and previous shims were trusting affected
by CVE-2020-14372, CVE-2020-25632, CVE-2020-25647, CVE-2020-27749,
  CVE-2020-27779, CVE-2021-20225, CVE-2021-20233, CVE-2020-10713,
  CVE-2020-14308, CVE-2020-14309, CVE-2020-14310, CVE-2020-14311, CVE-2020-15705,
  and if you were shipping the shim_lock module CVE-2021-3418
  ( July 2020 grub2 CVE list + March 2021 grub2 CVE list )
  grub2:
* were old shims hashes provided to Microsoft for verification
  and to be added to future DBX update ?
* Does your new chain of trust disallow booting old, affected by CVE-2020-14372,
  CVE-2020-25632, CVE-2020-25647, CVE-2020-27749,
  CVE-2020-27779, CVE-2021-20225, CVE-2021-20233, CVE-2020-10713,
  CVE-2020-14308, CVE-2020-14309, CVE-2020-14310, CVE-2020-14311, CVE-2020-15705,
  and if you were shipping the shim_lock module CVE-2021-3418
  ( July 2020 grub2 CVE list + March 2021 grub2 CVE list )
  grub2 builds ?
-------------------------------------------------------------------------------
N/A. This is our first submission.

-------------------------------------------------------------------------------
If your boot chain of trust includes linux kernel, is
"efi: Restrict efivar_ssdt_load when the kernel is locked down"
upstream commit 1957a85b0032a81e6482ca4aab883643b8dae06e applied ?
Is "ACPI: configfs: Disallow loading ACPI tables when locked down"
upstream commit 75b0cea7bf307f362057cc778efe89af4c615354 applied ?
-------------------------------------------------------------------------------
Both patches are applied.

-------------------------------------------------------------------------------
If you use vendor_db functionality of providing multiple certificates and/or
hashes please briefly describe your certificate setup. If there are allow-listed hashes
please provide exact binaries for which hashes are created via file sharing service,
available in public with anonymous access for verification
-------------------------------------------------------------------------------
We only embed out CA certificate (`lernstick-uefi-ca.der`). This CA is used to
sign further signing certificates which are used for signing the binaries. No
other hashes are added.

We currently use the following signing certificates for signing shim, grub and
Linux files.

 * Lernstick Secure Boot 2021 - linux (fingerprint: dbbb6641a16b478b875ae997eccc2fabedee49b089cfdbf069f7dd98d3ca3dc5)
 * Lernstick Secure Boot 2021 - GRUB 2 (fingerprint: 1ab883d4b7e3fec030ae631a717665492eda0dd42f2ecc58feea84f4e6886a32)
 * Lernstick Secure Boot 2021 - shim (fingerprint: cbac3fe7790ec70c73165245db0d61812e1b454415dbcabd4e9f63f5d8237300)

-------------------------------------------------------------------------------
If you are re-using a previously used (CA) certificate, you will need
to add the hashes of the previous GRUB2 binaries to vendor_dbx in shim
in order to prevent GRUB2 from being able to chainload those older GRUB2
binaries. If you are changing to a new (CA) certificate, this does not
apply. Please describe your strategy.
-------------------------------------------------------------------------------
We are using a new CA.

-------------------------------------------------------------------------------
What OS and toolchain must we use to reproduce this build?  Include where to find it, etc.  We're going to try to reproduce your build as close as possible to verify that it's really a build of the source tree you tell us it is, so these need to be fairly thorough. At the very least include the specific versions of gcc, binutils, and gnu-efi which were used, and where to find those binaries.
If the shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case and the differences would be.
-------------------------------------------------------------------------------
The easiest way to reproduce this build is with the supplied Dockerfile:

```
docker build . --no-cache
```

The following versions were used:

 * gcc: gcc-10_10.2.1-6
 * binutils: binutils_2.35.2-2
 * gnu-efi: gnu-efi_3.0.9-2
-------------------------------------------------------------------------------
Which files in this repo are the logs for your build?   This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
-------------------------------------------------------------------------------
`shim_15.4-6_amd64.build`

-------------------------------------------------------------------------------
Add any additional information you think we may need to validate this shim
-------------------------------------------------------------------------------
* This is our first submission.
* We (Research Center for Digital Sustainability) will be moving from Bern
  University to Bern University of Applied Sciences (BFH) later this year.
