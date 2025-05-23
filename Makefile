baurpm:
	mkdir -p build
	cc -o build/baurpm -lcurl -lcjson -larchive -lalpm baurpm.c

baurpm_debug:
	mkdir -p build
	cc -o build/baurpm-debug -lcurl -lcjson -larchive -lalpm -g -fsanitize=address -fsanitize=undefined baurpm.c

baurpm_test:
	cc -c -o /dev/null -lcurl -lcjson -larchive -lalpm -O -Wall -Wextra baurpm.c

baurpm_debug_test:
	cc -c -o /dev/null -lcurl -lcjson -larchive -lalpm -O -Wall -Wextra baurpm.c
	mkdir -p build
	cc -o build/baurpm-debug -lcurl -lcjson -larchive -lalpm -g -fsanitize=address -fsanitize=undefined baurpm.c

install:
	install -Dm0755 "build/baurpm" "/usr/bin/baurpm"
	install -Dm0644 -t "/usr/share/licenses/baurpm/" LICENSE.md
