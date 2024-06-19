FROM debian:bookworm
RUN apt-get update -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates

RUN apt-get update -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential wget git
COPY shimx64.efi /shim-review/shimx64.efi

# Download and verify the upstream source tarball for shim
RUN wget https://github.com/rhboot/shim/releases/download/15.8/shim-15.8.tar.bz2
RUN echo "a79f0a9b89f3681ab384865b1a46ab3f79d88b11b4ca59aa040ab03fffae80a9  shim-15.8.tar.bz2" > SHA256SUM
RUN sha256sum -c < SHA256SUM

# Rename the tarball to match what our packaging tools look for
RUN mv shim-15.8.tar.bz2 shim_15.8.orig.tar.bz2
RUN git clone https://github.com/Lernstick/shim
WORKDIR /shim
RUN git checkout lernstick_15.8-1-lernstick
RUN apt-get build-dep -y .
RUN dpkg-buildpackage -us -uc
WORKDIR /
RUN hexdump -Cv /shim/shim*.efi > build
RUN hexdump -Cv /shim-review/$(basename /shim/shim*.efi) > orig
RUN diff -u orig build
RUN sha256sum /shim/shim*.efi /shim-review/$(basename /shim/shim*.efi)

