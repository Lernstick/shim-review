FROM debian:bookworm
RUN apt-get update -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates

RUN apt-get update -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential wget git
COPY shimx64.efi /shim-review/shimx64.efi

# Download and verify the upstream source tarball for shim
RUN wget https://github.com/rhboot/shim/releases/download/16.0/shim-16.0.tar.bz2
RUN echo "d503f778dc75895d3130da07e2ff23d2393862f95b6cd3d24b10cbd4af847217  shim-16.0.tar.bz2" > SHA256SUM
RUN sha256sum -c < SHA256SUM

# Rename the tarball to match what our packaging tools look for
RUN mv shim-16.0.tar.bz2 shim_16.0.orig.tar.bz2
RUN git clone https://github.com/Lernstick/shim
WORKDIR /shim
RUN git checkout lernstick/16.0-1+lernstick.1
RUN apt-get build-dep -y .
RUN dpkg-buildpackage -us -uc
WORKDIR /
RUN hexdump -Cv /shim/shim*.efi > build
RUN hexdump -Cv /shim-review/$(basename /shim/shim*.efi) > orig
RUN diff -u orig build
RUN sha256sum /shim/shim*.efi /shim-review/$(basename /shim/shim*.efi)

