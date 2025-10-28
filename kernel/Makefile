CC = gcc
MUSL = musl
CFLAGS = --static -Os -fPIE -no-pie -fdata-sections -ffunction-sections
LDFLAGS = -Wl,-gc-sections -Wl,-strip-all

STRIP = strip
ROOTFS = rootfs_d.cpio
GZIP = gzip
UPX = upx
CP = cp

ifndef ROOTFS
	ROOTFS := rootfs_d.cpio
endif

all: extract/exp $(ROOTFS)
release: extract/exp $(ROOTFS)
debug: extract/debug $(ROOTFS)

extract/debug: exp.c kpwn.c
	@mkdir -p extract
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -DDEBUG
	$(STRIP) $@
	$(UPX) $@

extract/exp: exp.c kpwn.c
	@mkdir -p extract
	$(MUSL)-$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -DMUSL
	$(STRIP) $@
	$(UPX) $@
	$(CP) $@ .

$(ROOTFS): exp.c kpwn.c $(wildcard extract/*)
	cd ./extract || exit 1 && find . | cpio -o --format=newc >../$@

.PHONY: release all debug
