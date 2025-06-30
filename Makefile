LDFLAGS=-lcurl -lcjson -larchive -lalpm
DEBUG_FLAGS=-g -fsanitize=address -fsanitize=undefined
TEST_FLAGS=-c -o /dev/null $(LDFLAGS) -O -Wall -Wextra

baurpm:
	mkdir -p build
	cc -o build/baurpm $(LDFLAGS) baurpm.c

baurpm_debug:
	mkdir -p build
	cc -o build/baurpm-debug $(LDFLAGS) $(DEBUG_FLAGS) baurpm.c

baurpm_test:
	cc $(TEST_FLAGS) baurpm.c

baurpm_debug_test:  baurpm_test baurpm_debug

install:
	install -Dm0755 "build/baurpm" "/usr/bin/baurpm"
	install -Dm0644 -t "/usr/share/licenses/baurpm/" LICENSE.md
