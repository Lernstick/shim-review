FROM debian:bullseye
RUN echo "deb-src http://deb.debian.org/debian bullseye main" > /etc/apt/sources.list.d/deb-src.list
COPY files/lernstick-dpkg /etc/dpkg/origins/lernstick
RUN ln -sf /etc/dpkg/origins/lernstick /etc/dpkg/origins/default 

RUN apt-get update -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential git-buildpackage
COPY shimx64.efi /

RUN git clone https://github.com/Lernstick/shim
WORKDIR /shim 
RUN git checkout 15.6-1-lernstick
RUN apt-get build-dep -y .
RUN gbp buildpackage -us -uc --git-ignore-branch

RUN hexdump -Cv /shim/shim*.efi > build
RUN hexdump -Cv shimx64.efi > orig

RUN diff -u orig build
RUN sha256sum shimx64.efi /shim/shim*.efi
RUN objdump -s -j .sbat /shim/shim*.efi



