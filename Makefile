baurpm:
	mkdir -p build
	cc -o build/baurpm -lcurl -lcjson -larchive baurpm.c

baurpm_debug:
	mkdir -p build
	cc -o build/baurpm-debug -lcurl -lcjson -larchive -g -fsanitize=address -fsanitize=undefined baurpm.c

baurpm_test:
	cc -c -o /dev/null -lcurl -lcjson -larchive -O -Wall -Wextra baurpm.c

baurpm_debug_test:
	cc -c -o /dev/null -lcurl -lcjson -larchive -O -Wall -Wextra baurpm.c
	mkdir -p build
	cc -o build/baurpm-debug -lcurl -lcjson -larchive -g -fsanitize=address -fsanitize=undefined baurpm.c