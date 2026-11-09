#!/bin/bash
# Boot the arm64 kernel under QEMU TCG with an initramfs holding test_progs: run-arm64.sh <test_progs args...>
D=/workspaces/.agent-state/bpf-benchmark-supervisor
BA=$D/kfunc-copy-v2-build-arm64; OA=$D/kfunc-copy-v2-selftests-arm64; R=$D/kfunc-copy-v2-initramfs-arm64
ARGS="$*"
rm -rf $R; mkdir -p $R/bin $R/lib $R/proc $R/sys $R/dev $R/tmp $R/bpf
if [ ! -x $D/busybox-arm64/usr/bin/busybox ]; then
	(cd /tmp && apt-get download busybox-static:arm64 >/dev/null && dpkg-deb -x busybox-static_*_arm64.deb $D/busybox-arm64)
fi
cp $D/busybox-arm64/usr/bin/busybox $R/bin/
cp $OA/test_progs $OA/bpf_testmod.ko $R/bpf/
find_lib() { for d in /usr/aarch64-linux-gnu/lib /usr/lib/aarch64-linux-gnu /lib/aarch64-linux-gnu; do [ -e $d/$1 ] && { echo $d/$1; return; }; done; }
todo="$R/bpf/test_progs"
while [ -n "$todo" ]; do
	set -- $todo; f=$1; shift; todo="$*"
	for l in $(aarch64-linux-gnu-readelf -d $f | sed -n 's/.*Shared library: \[\(.*\)\]/\1/p'); do
		[ -e $R/lib/$l ] && continue
		src=$(find_lib $l); [ -z "$src" ] && { echo "missing $l"; continue; }
		cp -L $src $R/lib/$l; todo="$todo $R/lib/$l"
	done
done
cp -L /usr/aarch64-linux-gnu/lib/ld-linux-aarch64.so.1 $R/lib/
cat > $R/init <<EOI
#!/bin/busybox sh
/bin/busybox --install -s /bin
export PATH=/bin LD_LIBRARY_PATH=/lib
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev
mount -t debugfs none /sys/kernel/debug; mount -t tracefs none /sys/kernel/tracing
mount -t bpf none /sys/fs/bpf; mount -t tmpfs none /tmp
cd /bpf && /lib/ld-linux-aarch64.so.1 ./test_progs $ARGS
echo "TEST_PROGS_RC=\$?"
poweroff -f
EOI
chmod +x $R/init
(cd $R && find . | cpio -o -H newc 2>/dev/null | gzip -1) > $R.cpio.gz
ls -la $R.cpio.gz
timeout 3000 qemu-system-aarch64 -M virt -cpu max -accel tcg,thread=multi -smp 4 -m 4G -nographic -no-reboot \
	-kernel $BA/arch/arm64/boot/Image -initrd $R.cpio.gz -append "console=ttyAMA0 panic=-1 rdinit=/init"
