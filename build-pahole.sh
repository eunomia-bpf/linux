#!/bin/bash
set -e
W=/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2-work
sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y -q libdw-dev libelf-dev cmake python3-docutils >/dev/null
cd $W
[ -d dwarves ] || git clone -q https://git.kernel.org/pub/scm/devel/pahole/pahole.git dwarves || git clone -q https://github.com/acmel/dwarves.git dwarves
cd dwarves && git log --oneline -1 && mkdir -p build && cd build
cmake -D__LIB=lib -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=/usr/local .. >/dev/null
make -s -j24 && sudo -n make -s install >/dev/null
hash -r; /usr/local/bin/pahole --version
