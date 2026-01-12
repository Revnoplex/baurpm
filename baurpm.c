// Needs to be 700 instead of 500 in order for both nftw and strsignal to work
#define _XOPEN_SOURCE 700
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <dirent.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <archive.h>
#include <archive_entry.h>
#include <alpm.h>
#include <alpm_list.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <ftw.h>
#include <git2.h>
#include <sys/ioctl.h>

#define LONG_NAME "Basic Arch User Repository (AUR) Package Manager"
#define SHORT_NAME "baurpm"
#define VERSION "0.1.0a"
#define AUTHOR "Revnoplex"
#define LICENSE "MIT"
#define COPYRIGHT "Copyright (c) 2022-2026"
#define AUR_BASE_URL "https://aur.archlinux.org"
#define SUFFIX_MAX_SIZE sizeof("[ 100% ]")
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(*x))
#define PACMAN_DB_PATH "/var/lib/pacman"

struct winsize term_size;
struct timespec time_spec;
uint64_t last_spec = 0;

typedef int (*command_cb)(char *options, char *arguments[], int32_t arg_len, cJSON *package_data);
int command_h(char *options, char *arguments[], int32_t arg_len, cJSON *package_data);
int command_g(char *options, char *arguments[], int32_t arg_len, cJSON *package_data);
int command_i(char *options, char *arguments[], int32_t arg_len, cJSON *package_data);
int command_c(char *options, char *arguments[], int32_t arg_len, cJSON *package_data);

struct {
    command_cb callback;
    char name;
    char *description;
    char *usage;
    char *options[8];
} commands[] = {
    {
        command_h,
        'H',
        "Displays this message",
        " [Command name]",
        {}
    },
    {
        command_g,
        'G',
        "Get info on an AUR package",
        " [Package name]",
        {}
    },
    {
        command_i,
        'I',
        "Install an AUR package",
        "[Options] [Package/s to install. Tip: Specify \"-\" before a package name to ignore it]",
        {
            "f: Ignore any missing packages",
            "n: Skip reading PKGBUILD files",
            "d: Keep existing cache directories when extracting",
        }
    },
    {
        command_c,
        'C',
        "Check and Upgrade installed AUR packages",
        "[Options] [Package/s to ignore]",
        {
            "i, <packages>: Ignore upgrading packages specified",
            "f: Ignore any missing packages",
            "n: Skip reading PKGBUILD files",
            "s: Skip running pacman -Syu",
            "k: Upgrade archlinux-keyring first",
            "d: Keep existing cache directories when extracting",
        },
    },
};

typedef struct {
    char *name;
    char *version;
} InstalledPkgInfo;

typedef struct {
    char **conflicts;
    int conflicts_size;
    char **depends;
    int depends_size;
    char *description;
    int id;
    char **keywords;
    int keywords_size;
    char *name;
    char **opt_depends;
    int opt_depends_size;
    char **make_depends;
    int make_depends_size;
    char *base;
    int base_id;
    char *url_path;
    char *version;
} AURPkgInfo;

typedef struct {
    AURPkgInfo **items;
    int size;
} AURPkgInfoArray;

char **cjson_string_array_to_aop(cJSON *cjson_array, int *size_pointer) {
    *size_pointer = cJSON_GetArraySize(cjson_array);
    char **array_pointer = calloc(*size_pointer, sizeof(void *));
    if (array_pointer == NULL) {
        return NULL;
    }
    cJSON *item = NULL;
    int array_index = 0;
    cJSON_ArrayForEach(item, cjson_array) {
        if (item && item->valuestring) {
            array_pointer[array_index] = item->valuestring;
        }
        array_index++;
    }
    return array_pointer;
    
}

AURPkgInfo *new_aur_pkg_info(cJSON *pkg_data) {
    AURPkgInfo *pkg_info = calloc(1, sizeof(AURPkgInfo));
    if (pkg_info == NULL) {
        return NULL;
    }
    cJSON *data_pointer;

    if (
        (data_pointer = cJSON_GetObjectItemCaseSensitive(pkg_data, "Conflicts")) && cJSON_IsArray(data_pointer)
        && (pkg_info->conflicts = cjson_string_array_to_aop(data_pointer, &pkg_info->conflicts_size)) == NULL
    ) {
        return NULL;
    }
    if (
        (data_pointer = cJSON_GetObjectItemCaseSensitive(pkg_data, "Depends")) && cJSON_IsArray(data_pointer)
        && (pkg_info->depends = cjson_string_array_to_aop(data_pointer, &pkg_info->depends_size)) == NULL
    ) {
        return NULL;
    }
    if ((data_pointer = cJSON_GetObjectItemCaseSensitive(pkg_data, "Description")) && data_pointer->valuestring) {
        pkg_info->description = data_pointer->valuestring;
    }
    if ((data_pointer = cJSON_GetObjectItemCaseSensitive(pkg_data, "ID")) && data_pointer->valueint) {
        pkg_info->id = data_pointer->valueint;
    }
    if (
        (data_pointer = cJSON_GetObjectItemCaseSensitive(pkg_data, "Keywords")) && cJSON_IsArray(data_pointer)
        && (pkg_info->keywords = cjson_string_array_to_aop(data_pointer, &pkg_info->keywords_size)) == NULL
    ) {
        return NULL;
    }
    if ((data_pointer = cJSON_GetObjectItemCaseSensitive(pkg_data, "Name")) && data_pointer->valuestring) {
        pkg_info->name = data_pointer->valuestring;
    }
    if (
        (data_pointer = cJSON_GetObjectItemCaseSensitive(pkg_data, "OptDepends")) && cJSON_IsArray(data_pointer)
        && (pkg_info->opt_depends = cjson_string_array_to_aop(data_pointer, &pkg_info->opt_depends_size)) == NULL
    ) {
        return NULL;
    }
     if (
        (data_pointer = cJSON_GetObjectItemCaseSensitive(pkg_data, "MakeDepends")) && cJSON_IsArray(data_pointer)
        && (pkg_info->make_depends = cjson_string_array_to_aop(data_pointer, &pkg_info->make_depends_size)) == NULL
    ) {
        return NULL;
    }
    if ((data_pointer = cJSON_GetObjectItemCaseSensitive(pkg_data, "PackageBase")) && data_pointer->valuestring) {
        pkg_info->base = data_pointer->valuestring;
    }
    if ((data_pointer = cJSON_GetObjectItemCaseSensitive(pkg_data, "PackageBaseID")) && data_pointer->valueint) {
        pkg_info->base_id = data_pointer->valueint;
    }
    if ((data_pointer = cJSON_GetObjectItemCaseSensitive(pkg_data, "URLPath")) && data_pointer->valuestring) {
        pkg_info->url_path = data_pointer->valuestring;
    }
    if ((data_pointer = cJSON_GetObjectItemCaseSensitive(pkg_data, "Version")) && data_pointer->valuestring) {
        pkg_info->version = data_pointer->valuestring;
    }

    return pkg_info;
}

AURPkgInfoArray *new_aur_pkg_info_array(cJSON *pkg_list) {
    cJSON *pkg_data;
    AURPkgInfoArray *pkg_info_array = malloc(sizeof(AURPkgInfoArray));
    if (pkg_info_array == NULL) {
        return NULL;
    }
    pkg_info_array->size = cJSON_GetArraySize(pkg_list);
    pkg_info_array->items = calloc(pkg_info_array->size, sizeof(void *));
    if (pkg_info_array->items == NULL) {
        return NULL;
    }
    
    int idx = 0;
    cJSON_ArrayForEach(pkg_data, pkg_list) {
        AURPkgInfo *pkg_info = new_aur_pkg_info(pkg_data);
        if (pkg_info == NULL) {
            return NULL;
        }
        pkg_info_array->items[idx] = pkg_info;
        idx++;
    }
    return pkg_info_array;
}

typedef void (*free_cb)(void *pointer);

void aop_members_free(void **array, uint64_t array_size, free_cb callback) {
    if (array == NULL) return;
    for (uint64_t idx = 0; idx < array_size; idx++) {
        callback(array[idx]);
    }
}

void aop_full_free(void **array, uint64_t array_size, free_cb members_callback, free_cb outer_callback) {
    aop_members_free(array, array_size, members_callback);
    outer_callback(array);
}

void aur_pkg_info_reference_free(AURPkgInfo *pointer) {
   if (pointer == NULL) return;
    free(pointer->conflicts);
    free(pointer->depends);
    free(pointer->keywords);
    free(pointer->opt_depends);
    free(pointer->make_depends);
    free(pointer);
}

void aur_pkg_info_array_free(AURPkgInfoArray *pointer) {
    if (pointer == NULL) return;
    aop_full_free(
        (void **)pointer->items, 
        pointer->size, 
        (free_cb)aur_pkg_info_reference_free, 
        free
    );
    free(pointer);
}

void installed_pkg_info_free(InstalledPkgInfo *pointer) {
    if (pointer == NULL) return;
    free(pointer->name);
    free(pointer->version);
    free(pointer);
}

void installed_pkg_info_array_free(InstalledPkgInfo **pointer, uint32_t size) {
    aop_full_free(
        (void **)pointer, 
        size, 
        (free_cb)installed_pkg_info_free, 
        free
    );
}



struct memory {
    /*
    Source: https://github.com/curl/curl/blob/master/docs/libcurl/opts/CURLOPT_WRITEFUNCTION.md
    Copyright: https://github.com/curl/curl/blob/master/COPYING
    SPDX-License-Identifier: curl
    */
    char *response;
    size_t size;
  };

typedef struct progress_data {
	git_indexer_progress fetch_progress;
    const char *operation;
	const char *path;
} progress_data;

/*
    Exit codes:
    0: OK
    1: User Error
    2: Requested Resource Not Found
    3: Filesystem Related Errors
    4: 3rd party errors
    5: Web Errors
    6: Unexpected return/contents/reponse
    7: Parsing related errors
    8: Unintended Behaviour
    9: Buffer exhausted
    10: Miscellanious

    32+: makepkg errors
    64+: pacman errors
    128+: signals
    */
   

int rmrf(const char *path, const struct stat *stat_info, int typeflag, struct FTW *ftwbuf) {
    (void)(stat_info);
    (void)(typeflag);
    (void)(ftwbuf);
    int rm_status;
    if ((rm_status = remove(path))) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to remove %s: %s\n", path, strerror(errno));
    }
    return rm_status;
}

static size_t cb(char *data, size_t size, size_t nmemb, void *clientp) {
    /* 
    Source: https://github.com/curl/curl/blob/master/docs/libcurl/opts/CURLOPT_WRITEFUNCTION.md
    Copyright: https://github.com/curl/curl/blob/master/COPYING
    SPDX-License-Identifier: curl
    */
    size_t realsize = size * nmemb;
    struct memory *mem = (struct memory *)clientp;

    char *ptr = realloc(mem->response, mem->size + realsize + 1);
    if(!ptr)
        return 0;  /* out of memory */

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), data, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;

    return realsize;
}

static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream) {
    /*
    Source: https://github.com/curl/curl/blob/master/docs/examples/url2file.c
    Copyright: https://github.com/curl/curl/blob/master/COPYING
    SPDX-License-Identifier: curl
    */
    size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
    return written;
}

static int copy_data(struct archive *ar, struct archive *aw) {
    /*
    Source: https://github.com/libarchive/libarchive/blob/master/examples/untar.c
    Copyright: https://github.com/libarchive/libarchive/blob/master/COPYING
    The above source file in the URL is in the public domain.
    */
	int r;
	const void *buff;
	size_t size;
    
#if ARCHIVE_VERSION_NUMBER >= 3000000
	int64_t offset;
#else
	off_t offset;
#endif

	for (;;) {
		r = archive_read_data_block(ar, &buff, &size, &offset);
		if (r == ARCHIVE_EOF)
			return (ARCHIVE_OK);
		if (r != ARCHIVE_OK)
			return (r);
		r = archive_write_data_block(aw, buff, size, offset);
		if (r != ARCHIVE_OK) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: archive_write_data_block() failed: %s\n", archive_error_string(aw));
			return (r);
		}
	}
}

static int extract(const char *filename, int32_t keep_existing) {
    /*
    Source: https://github.com/libarchive/libarchive/blob/master/examples/untar.c
    Copyright: https://github.com/libarchive/libarchive/blob/master/COPYING
    The above source file in the URL is in the public domain.
    The code below has been modified to match specific needs.
    */
    const char *err_msg_prefix = "\x1b[1;31mFatal\x1b[0m: An Error occured while extracting the package: "; 
    int flags = ARCHIVE_EXTRACT_TIME;
    flags |= ARCHIVE_EXTRACT_PERM;
    flags |= ARCHIVE_EXTRACT_ACL;
    flags |= ARCHIVE_EXTRACT_FFLAGS;
	struct archive *a;
	struct archive *ext;
	struct archive_entry *entry;
	int r;

	a = archive_read_new();
	ext = archive_write_disk_new();
	archive_write_disk_set_options(ext, flags);
	
	archive_read_support_format_tar(a);
    archive_read_support_filter_gzip(a);

	if ((r = archive_read_open_filename(a, filename, 10240))) {
        fprintf(stderr, "%sarchive_read_open_filename() error: %s\n", err_msg_prefix, archive_error_string(a));
        archive_read_close(a);
        archive_read_free(a);
        
        archive_write_close(ext);
        archive_write_free(ext);
        return r;
    }
	for (;;) {
		r = archive_read_next_header(a, &entry);
		if (r == ARCHIVE_EOF) {
            break;
        }
		if (r != ARCHIVE_OK) {
            fprintf(stderr, "%sarchive_read_next_header() error: %s\n", err_msg_prefix, archive_error_string(a));
            archive_read_close(a);
            archive_read_free(a);
            archive_write_close(ext);
            archive_write_free(ext);
            return r;
        }
        const char *entry_pathname = archive_entry_pathname(entry);
        if (entry_pathname != NULL && !keep_existing) {
            struct stat stat_info;
            int stat_status = stat(entry_pathname, &stat_info);
            if (stat_status == 0 && S_ISDIR(stat_info.st_mode)) {
                printf("Directory %s exists. Deleting to prevent issues with PKGBUILD scripts...\n", entry_pathname);
                int rmrf_successful = nftw(entry_pathname, rmrf, 64, FTW_DEPTH | FTW_PHYS);
                if(rmrf_successful) {
                    fprintf(stderr, "\x1b[1;31mError\x1b[0m: Removing directory %s failed: %s\n", entry_pathname, strerror(errno));
                }
            }
        }
        r = archive_write_header(ext, entry);
        if (r != ARCHIVE_OK) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: failed to write %s: %s\n", archive_entry_pathname(entry), archive_error_string(ext));
        }
        else {
            r = copy_data(a, ext);
            if (r != ARCHIVE_OK) {
                fprintf(stderr, "%scopy_data() error: %s\n", err_msg_prefix, archive_error_string(ext));
                archive_read_close(a);
                archive_read_free(a);

                archive_write_close(ext);
                archive_write_free(ext);
                return r;
            }
            r = archive_write_finish_entry(ext);
            if (r != ARCHIVE_OK) {
                fprintf(stderr, "%sarchive_write_finish_entry() error: %s\n", err_msg_prefix, archive_error_string(ext));
                archive_read_close(a);
                archive_read_free(a);

                archive_write_close(ext);
                archive_write_free(ext);
                return r;
            }
        }

		
	}
	archive_read_close(a);
	archive_read_free(a);
	
	archive_write_close(ext);
  	archive_write_free(ext);
	return 0;
}

char **find_missing(char *superv[], int32_t superc, char *subv[], int32_t subc) {
    char **missing = malloc(superc * sizeof(void *));
    uint32_t missing_idx = 0;
    for (int32_t superi = 0; superi < superc; superi++)  {
        uint8_t found = 0;
        for (int32_t subi = 0; subi < subc; subi++) {
            for (int32_t chari = 0; superv[superi][chari] == subv[subi][chari]; chari++) {
                if (superv[superi][chari] == '\0') {
                    found = 1;
                    break;
                } else if (subv[subi][chari] == '\0') {
                }
            }
        }
        if (!found) {
            missing[missing_idx] = superv[superi];
            missing_idx++;
        }
    }
    return missing;
}

void print_string_array(char *stringsv[], uint32_t stringsc) {
    for (uint32_t stringsi = 0; stringsi < stringsc; stringsi++) {
        if (stringsi) {
            printf(", ");
        }
        printf("%s", stringsv[stringsi]);
    }
}

void print_cjson_string_array(cJSON *array) {
    const cJSON *item = NULL;
    uint8_t first = 1;
    cJSON_ArrayForEach(item, array) {
        if (first) {
            first = 0;
        } else {
            printf(", ");
        }
        if (cJSON_IsString(item)) {
            printf("%s", item->valuestring);
        }
    }
}

uint64_t u64_pow(uint32_t num, uint8_t exp) {
    uint64_t result = 1;
    for (uint8_t i = 0; i < exp; ++i) {
            result *= num;
    }
    return result;
}


char *byte_units(uint64_t byte_size) {
    // represents a number of bytes derived iec units.
    // max size: 16 exabytes (EiB)

    // stores derived units to display
    char unit_names[][6] = { 
        "bytes", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB" 
    };

    // calculate the utilised bits used to represent the number.
    int8_t bit_length = 0;
    for (uint64_t bit = byte_size; bit; bit>>=1) {
        bit_length++;
    }
    
    // use the number of utilised bits to calculate the exponent.
    uint8_t xp = 
        (bit_length-1)*((bit_length-1 > 0) - (bit_length-1 < 0)) / 10
    ;

    // create buffer to store the string representation
    uint8_t buffer_size = 18;
    char *rep_buffer = malloc(buffer_size);
    if (rep_buffer == NULL) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Memory allocation error: %s\n", strerror(errno));
        return NULL;
    }

    // construct the string with 4 significant figures
    if (
        snprintf(
            rep_buffer, buffer_size, "%.4g %s", 
            (double) byte_size/u64_pow(1024, xp), 
            (byte_size == 1) ? "byte" : unit_names[xp]
        ) < 0
    ) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Couldn't concatenate string: %s\n", strerror(errno));
        return NULL;
    }
    return rep_buffer;
}

cJSON *find_pkg(char *package_names[], int32_t pkg_len, uint8_t ignore_missing, uint8_t *status) {
    const char *err_msg_prefix = "\x1b[1;31mFatal\x1b[0m: Failed to get information on the package/s: "; 
    if (!pkg_len) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: No packages were given to look for.\n");
        *status = 8;
        return cJSON_CreateNull();
    }
    uint32_t url_args_size = 0;
    for (int32_t pkg_idx = 0; pkg_idx < pkg_len; pkg_idx++) {
        url_args_size += 7;
        for (int32_t name_idx = 0; package_names[pkg_idx][name_idx] != '\0'; name_idx++) {
            url_args_size++;
        }
    }

    char *url_args = malloc(url_args_size+1);

    int32_t url_args_idx = 0;
    for (int32_t pkg_idx = 0; pkg_idx < pkg_len; pkg_idx++) {
        char delimiter[] = "&arg[]=";
        int32_t del_idx;
        for (del_idx = 0; del_idx < 7; del_idx++) {
            url_args[url_args_idx] = delimiter[del_idx];
            url_args_idx++;
        }
        int32_t name_idx;
        for (name_idx = 0; package_names[pkg_idx][name_idx] != '\0'; name_idx++) {
            url_args[url_args_idx] = package_names[pkg_idx][name_idx];
            url_args_idx++;
        }
    }
    url_args[url_args_size] = '\0';

    struct memory chunk = {0};
    CURL *curl;
    CURLcode res;
    char api_version = '5';
    char api_url_prefix[] = "/rpc?v=";
    char other_params[] = "&type=info";

    int32_t url_size = sizeof(AUR_BASE_URL) + sizeof(api_url_prefix) - 2 + sizeof(api_version) + sizeof(other_params)-1 + url_args_size;
    char *url_buffer = malloc(url_size+1);

    snprintf(url_buffer, url_size+1, "%s%s%c%s%s", AUR_BASE_URL, api_url_prefix, api_version, other_params, url_args);
    free(url_args);

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url_buffer);

        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);

        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    
        /* Perform the request, res gets the return code */
        res = curl_easy_perform(curl);
        free(url_buffer);
        /* Check for errors */
        if (res) {
            fprintf(stderr, "%scURL Error %d: %s\n", err_msg_prefix, res, curl_easy_strerror(res));
            *status = 5;
            curl_easy_cleanup(curl);
            return cJSON_CreateNull();
        }
        struct curl_header *content_type;
        CURLHcode header_error;
        header_error = curl_easy_header(curl, "Content-Type", 0, CURLH_HEADER, -1, &content_type);
        if (header_error) {
            fprintf(
                stderr, 
                "%sFailed to get content type: cURL Error %d\n", 
                err_msg_prefix, header_error
            );
            curl_easy_cleanup(curl);
            free(chunk.response);
            *status = 5;
            return cJSON_CreateNull();
        }
        char type_match[] = "application/json";
        for (uint8_t type_idx = 0; type_idx < sizeof(type_match); type_idx++) {
            if (content_type->value[type_idx] != type_match[type_idx]) {
                long response_code;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
                if (response_code >= 400) {
                    fprintf(stderr, "%sHTTP Error %ld\n", err_msg_prefix, response_code);
                    *status = 5;
                    curl_easy_cleanup(curl);
                    free(chunk.response);
                    return cJSON_CreateNull();
                }
                fprintf(stderr, "%sExcpected a %s response, got a %s response instead.\n", err_msg_prefix, type_match, content_type->value);
                curl_easy_cleanup(curl);
                free(chunk.response);
                *status = 6;
                return cJSON_CreateNull();
            }
        }

        cJSON *parsed_response = cJSON_Parse(chunk.response);
        if (parsed_response == NULL) {
            const char *error_ptr = cJSON_GetErrorPtr();
            if (error_ptr) {
                fprintf(stderr, "%scJSON Error: parsing error around char %lu\n", err_msg_prefix, error_ptr-chunk.response);
            } else {
                fprintf(stderr, "%scJSON Error", err_msg_prefix);
            }
            curl_easy_cleanup(curl);
            free(chunk.response);
            *status = 7;
            return cJSON_CreateNull();
        }
        free(chunk.response);

        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

        curl_easy_cleanup(curl);

        cJSON *aur_response_type_key = cJSON_GetObjectItemCaseSensitive(parsed_response, "type");
        char *aur_response_type;
        if ((aur_response_type_key && aur_response_type_key->valuestring)) {
            aur_response_type = aur_response_type_key->valuestring;
        } else {
            *status = 6;
            fprintf(stderr, "%sMissing JSON key in API response: 'type'\n", err_msg_prefix);
            return parsed_response;
        }

        char error_match[] = "error";
        if (response_code >= 400) {
            for (uint8_t err_idx = 0; aur_response_type[err_idx] == error_match[err_idx]; err_idx++) {
                if (err_idx == sizeof(error_match)-1) {
                    cJSON *error_key = cJSON_GetObjectItemCaseSensitive(parsed_response, "error");
                    if (error_key && error_key->valuestring) {
                        fprintf(stderr, "%sAURWEB RPC Error: %s\n", err_msg_prefix, error_key->valuestring);
                    } else {
                        fprintf(stderr, "%sAURWEB RPC Error\n", err_msg_prefix);
                    }
                    *status = 5;
                    return parsed_response;
                }
            }
            fprintf(stderr, "%sHTTP Error %ld\n", err_msg_prefix, response_code);
            *status = 5;
            return parsed_response;
        }
        for (uint8_t err_idx = 0; aur_response_type[err_idx] == error_match[err_idx]; err_idx++) {
            if (err_idx == sizeof(error_match)-1) {
                cJSON *error_key = cJSON_GetObjectItemCaseSensitive(parsed_response, "error");
                if (error_key && error_key->valuestring) {
                    fprintf(stderr, "%sAURWEB RPC Error: %s\n", err_msg_prefix, error_key->valuestring);
                } else {
                    fprintf(stderr, "%sAURWEB RPC Error\n", err_msg_prefix);
                }
                *status = 5;
                return parsed_response;
            }
        }
        cJSON *result_count_key = cJSON_GetObjectItemCaseSensitive(parsed_response, "resultcount");
        int32_t result_count;
        if (result_count_key && cJSON_IsNumber(result_count_key)) {
            result_count = result_count_key->valueint;
        } else {
            *status = 6;
            fprintf(stderr, "%sMissing JSON key in API response: 'resultcount'\n", err_msg_prefix);
            return parsed_response;
        }
        if (result_count < pkg_len && !ignore_missing) {
            *status = 2;
            cJSON *found_packages = cJSON_GetObjectItemCaseSensitive(parsed_response, "results");
            const cJSON *package = NULL;
            // using actual array size instead of result_count in case they differ which would cause oob access.
            uint32_t found_pkg_arrc = cJSON_GetArraySize(found_packages);
            char **found_pkg_names = malloc(found_pkg_arrc * sizeof(void *));
            uint32_t pkgsc = 0;
            cJSON_ArrayForEach(package, found_packages) {
                cJSON *name = cJSON_GetObjectItemCaseSensitive(package, "Name");
                if (name && name->valuestring) {
                    found_pkg_names[pkgsc] = name->valuestring;
                    pkgsc++;
                }
            }
            char **missing_pkgs = find_missing(package_names, pkg_len, found_pkg_names, pkgsc);
            printf("The following packages could not be found: ");
            for (uint32_t arri = 0; arri < pkg_len-pkgsc; arri++) {
                if (arri == pkg_len-pkgsc-1) {
                    printf("%s", missing_pkgs[arri]);
                } else {
                    printf("%s, ", missing_pkgs[arri]);
                }
            }
            printf("\n");
            free(missing_pkgs);
            free(found_pkg_names);
            return parsed_response;
        }
        *status = 0;
        return parsed_response;
    }
    free(url_buffer);
    curl_easy_cleanup(curl);
    fprintf(stderr, "%scURL init failure\n", err_msg_prefix);
    *status = 4;
    return cJSON_CreateNull();

}

char *download_pkg(char *url_path, uint8_t *status) {
    const char *err_msg_prefix = "\x1b[1;31mFatal\x1b[0m: Failed to download the package: "; 
    uid_t uid = getuid();
    struct passwd* pwd = getpwuid(uid);

    if (!pwd) {
        fprintf(stderr, "%sCould not get home directory\n", err_msg_prefix);
        *status = 3;
        return "";
    }
    uint32_t hdirc;
    for (hdirc = 0; pwd->pw_dir[hdirc] != '\0'; hdirc++);
    char cache_dir[] = ".cache";
    uint32_t dirc = hdirc + sizeof(cache_dir) + 1;
    char *cache_dir_buffer = malloc(dirc);
    snprintf(cache_dir_buffer, dirc, "%s/%s", pwd->pw_dir, cache_dir);
    mkdir(cache_dir_buffer, 0777);
    free(cache_dir_buffer);
    char baurpm_dir[] = ".cache/baurpm";
    dirc = hdirc + sizeof(baurpm_dir) + 1;
    char *baurpm_dir_buffer = malloc(dirc);
    snprintf(baurpm_dir_buffer, dirc, "%s/%s", pwd->pw_dir, baurpm_dir);
    mkdir(baurpm_dir_buffer, 0777);
    free(baurpm_dir_buffer);
    char downloads_dir[] = ".cache/baurpm/downloads";
    dirc = hdirc + sizeof(downloads_dir) + 1;
    char *downloads_dir_buffer = malloc(dirc);
    snprintf(downloads_dir_buffer, dirc, "%s/%s", pwd->pw_dir, downloads_dir);
    mkdir(downloads_dir_buffer, 0777);
    
    char *file_name_buffer = NULL;
    int32_t slash_index = -1;
    uint8_t found_last_slash = 0;
    uint32_t sizeof_url_path = 0;
    for (uint32_t url_idx = 0;; url_idx++) {
        if (url_path[url_idx] == '/') {
            slash_index = url_idx;
        }
        if (found_last_slash) {
            if (!file_name_buffer) {
                file_name_buffer = malloc(sizeof_url_path-slash_index);
            }
            file_name_buffer[url_idx-slash_index-1] = url_path[url_idx];
        }
        if (url_path[url_idx] == '\0') {
            if (slash_index > -1 && !found_last_slash) {
                sizeof_url_path = url_idx;
                url_idx = slash_index;
                found_last_slash = 1;
                continue;
            }
            break;
        }
    }
    if (!file_name_buffer) {
        fprintf(stderr, "%s Failed to extract filename from URL provided by the API", err_msg_prefix);
        *status = 7;
        return "";
    }
    uint32_t path_size = dirc + sizeof_url_path-slash_index;
    char *download_path = malloc(path_size);
    snprintf(download_path, path_size, "%s/%s", downloads_dir_buffer, file_name_buffer);
    
    // free(downloads_dir_buffer);
    
    CURL *curl;
    CURLcode res;
    
    // we need to calculate the size of url_path
    uint32_t url_path_size;
    for (url_path_size = 0; url_path[url_path_size] != '\0'; url_path_size++);
    /* note that this does not include the null terminator but sizeof(AUR_BASE_URL) does. 
    So we will get space for a terminator at the end */
    
    // calculate the url buffer size
    // should be the addition of the sizes of 2 parts: the base url and the url path
    uint32_t url_size = sizeof(AUR_BASE_URL) + url_path_size;
    
    // then allocate the buffer for the url
    char *url_buffer = malloc(url_size);
   
    // then construct the url
    snprintf(url_buffer, url_size, "%s%s", AUR_BASE_URL, url_path);

    // initialise curl
    curl = curl_easy_init();
    // check if curl initialised sucessfully
    if(curl) {
        // set the url
        curl_easy_setopt(curl, CURLOPT_URL, url_buffer);

        /* some urls redirect and curl doesn't follow them by default,
        meaning we might never reach the page with what we need */
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);

        // tell curl how to write to a file.
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);

        // define the variable to store the pointer to where our file is opened
        FILE *download_ptr;

        // open our file for writing
        download_ptr = fopen(download_path, "wb");

        // tell cURL to write the response to the file.
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, download_ptr);

        char base_prefix[] = "https://";

        char *aur_netloc = malloc(sizeof(AUR_BASE_URL)-sizeof(base_prefix)+1);
        for (uint32_t idx = sizeof(base_prefix) - 1; idx < sizeof(AUR_BASE_URL); idx++) {
            aur_netloc[idx - sizeof(base_prefix) + 1] = AUR_BASE_URL[idx];
        }

        printf("Connecting to %s", aur_netloc);
        /* 
        need to flush stdout or the above won't get displayed
        until the next newline is printed which is too late.
        */
        fflush(stdout);

        /* Perform the request, res gets the return code */
        res = curl_easy_perform(curl);

        uint64_t download_size = ftell(download_ptr);
        /* once the request has been performed, 
        it would have finished writing to the file as it is a blocking call.
        So we can close it now */
        fclose(download_ptr);
        // And we won't need the url anymore.
        // except now
        // free(url_buffer);

        /* Check for errors */
        if (res) {
            fprintf(stderr, "\r\x1b[1;31mError\x1b[0m: cURL error %d: %s\n", res, curl_easy_strerror(res));
            *status = 5;
            free(downloads_dir_buffer);
            free(url_buffer);
            free(file_name_buffer);
            curl_easy_cleanup(curl);
            free(aur_netloc);
            return download_path;
        }
        struct curl_header *content_type;
        CURLHcode header_error;
        header_error = curl_easy_header(curl, "Content-Type", 0, CURLH_HEADER, -1, &content_type);
        if (header_error) {
            fprintf(
                stderr, 
                "\r%sFailed to get content type: cURL Error %d\n", 
                err_msg_prefix, header_error
            );
            *status = 5;
            free(downloads_dir_buffer);
            free(url_buffer);
            free(file_name_buffer);
            curl_easy_cleanup(curl);
            free(aur_netloc);
            return download_path;
        }
        char type_match[] = "application/x-gzip";
        for (uint8_t type_idx = 0; type_idx < sizeof(type_match); type_idx++) {
            if (content_type->value[type_idx] != type_match[type_idx] && content_type->value[type_idx] != ';') {
                long response_code;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
                if (response_code >= 400) {
                    fprintf(stderr, "\r%sHTTP Error %ld\n", err_msg_prefix, response_code);
                    *status = 5;
                    free(file_name_buffer);
                    free(downloads_dir_buffer);
                    free(url_buffer);
                    curl_easy_cleanup(curl);
                    free(aur_netloc);
                    return download_path;
                }
                fprintf(stderr, "\r\x1b[1;31mError\x1b[0m: Excpected a %s response, got a %s response instead.\n", type_match, content_type->value);
                free(downloads_dir_buffer);
                free(url_buffer);
                *status = 0;
                free(file_name_buffer);
                curl_easy_cleanup(curl);
                free(aur_netloc);
                return download_path;
            }
        }
        free(downloads_dir_buffer);
        free(url_buffer);

        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

        // That is the last usage of curl so we can free it from memory.
        curl_easy_cleanup(curl);

        // Check for HTTP errors
        if (response_code >= 400) {
            fprintf(stderr, "\r\x1b[1;31mError\x1b[0m: HTTP error %ld          \n", response_code);
            *status = 5;
            free(file_name_buffer);
            free(aur_netloc);
            return download_path;
        }
        char *derived_size = byte_units(download_size);
        printf("\rDownloaded %s (%s) from %s\n", file_name_buffer, derived_size, aur_netloc);
        free(file_name_buffer);
        free(derived_size);
        free(aur_netloc);
        *status = 0;
        return download_path;
    }
    // This code will be reached if curl fails to initialise.
    // we will never be able to use the url now so we can release it.
    free(url_buffer);
    free(file_name_buffer);
    // along with curl
    curl_easy_cleanup(curl);
    fprintf(stderr, "%scURL init failure\n", err_msg_prefix);
    *status = 4;
    return download_path;

}

char *retry_download_pkg(char *url_path, uint8_t *status) {
    char *result = NULL;
    int32_t retries = 0;
    do {
        if (retries >= 10) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Failed to download the package: Max retry attempts exceeded\n");
            break;
        }
        if (retries > 0) {
            printf("Retrying in 5 seconds...\n");
            sleep(5);
        }
        if (result != NULL) {
            free(result);
        }
        result = download_pkg(url_path, status);
        retries++;
    } while (*status == 5 || *status == 4);
    return result;
}

char *progress_bar(uint16_t columns, char *prefix, int32_t prefix_size, char *suffix, int32_t suffix_size, uint64_t numerator, uint64_t denominator) {
    if (!denominator) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Got unexpected zero value while creating progress bar!\n");
        return NULL;
    }
    for (int32_t idx = prefix_size; idx < columns+1; idx++) {
        prefix[idx] = ' ';
    }
    for (int32_t idx = 0; idx < suffix_size; idx++) {
        prefix[columns-suffix_size+idx] = suffix[idx];
    }
    prefix[columns] = '\0';
    char *full_bar = malloc(columns+9);
    if (full_bar == NULL) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Memory allocation error: %s\n", strerror(errno));
        return NULL;
    }
    char escape_prefix[] = "\x1b[7m";
    if (snprintf(full_bar, sizeof(escape_prefix), "%s", escape_prefix) < 0) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Couldn't concatenate string: %s\n", strerror(errno));
        return NULL;
    }
    char insert[] = "\x1b[0m";
    int32_t insert_offset = columns*numerator / denominator;
    for (int32_t idx = 4; idx < columns+9; idx++) {
        if (idx >= insert_offset+4 && idx < insert_offset+4+4) {
            full_bar[idx] = insert[idx-insert_offset-4];
        } else {
            if (idx <= columns+8) {
                int32_t data_offset = 4;
                if (idx >= insert_offset+4) {
                    data_offset = 8;
                }
                full_bar[idx] = prefix[idx-data_offset];
            } else {
                full_bar[idx] = 'E';
            }
        }
    }
    full_bar[columns+9-1] = '\0';
    return full_bar;
}

static int print_progress(const progress_data *pd) {
    if (ioctl(1, TIOCGWINSZ, &term_size) == -1) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Could't get terminal size: ioctl error %d: %s\n", errno, strerror(errno));
        return -1;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &time_spec) == -1) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Couldn't get timestamp: errno %d: %s\n", errno, strerror(errno));
        return -1;
    }
    uint64_t duration_elapsed = time_spec.tv_sec * 1000000 + time_spec.tv_nsec / 1000 - last_spec;
    last_spec = last_spec ? last_spec : (uint64_t) time_spec.tv_sec * 1000000 + time_spec.tv_nsec / 1000;
    double seconds_elasped = (double) duration_elapsed / 1000000;
    uint64_t download_rate = pd->fetch_progress.received_bytes / seconds_elasped;

    char *prefix = malloc(term_size.ws_col+1);
    if (prefix == NULL) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Memory allocation error: %s\n", strerror(errno));
        return -1;
    }
    int32_t prefix_size;
    int32_t suffix_size;
    char *suffix;
    char *full_bar;
	int network_percent = pd->fetch_progress.total_objects > 0 ?
		(100*pd->fetch_progress.received_objects) / pd->fetch_progress.total_objects :
		0;
	int index_percent = pd->fetch_progress.total_objects > 0 ?
		(100*pd->fetch_progress.indexed_objects) / pd->fetch_progress.total_objects :
		0;
    int delta_percent = pd->fetch_progress.total_deltas > 0 ?
		(100*pd->fetch_progress.indexed_deltas) / pd->fetch_progress.total_deltas :
		0;
    int numerator = pd->fetch_progress.received_objects+pd->fetch_progress.indexed_objects+pd->fetch_progress.indexed_deltas;
    int denominator = pd->fetch_progress.total_objects > 0 ? 2*pd->fetch_progress.total_objects+pd->fetch_progress.indexed_deltas : 1;
    int total_percent = (100*numerator) / denominator;
	char *download_bytes = byte_units(pd->fetch_progress.received_bytes);
    if (download_bytes == NULL) {
        return -1;
    }
    char *download_bytes_rate = byte_units(download_rate);
    if (download_bytes_rate == NULL) {
        return -1;
    }
    prefix_size = snprintf(prefix, term_size.ws_col+1, 
        "%s %s: Download: [%s, %s/s, %5u/%5u] (%3d%%), Idx: %5u/%5u (%3d%%), Delta: %5u/%5u (%3d%%)",
        pd->operation, pd->path, 
        download_bytes, download_bytes_rate, pd->fetch_progress.received_objects, pd->fetch_progress.total_objects, network_percent, 
        pd->fetch_progress.indexed_objects, pd->fetch_progress.total_objects, index_percent,
        pd->fetch_progress.indexed_deltas, pd->fetch_progress.total_deltas, delta_percent
    );
    if (prefix_size < 0) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Couldn't concatenate string: %s\n", strerror(errno));
        return -1;
    }
    
    if ((suffix = malloc(SUFFIX_MAX_SIZE)) == NULL) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Memory allocation error: %s\n", strerror(errno));
        return -1;
    }
    
    if ((suffix_size = snprintf(suffix, SUFFIX_MAX_SIZE, "[ %3d%% ]", total_percent)) < 0) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Couldn't concatenate string: %s\n", strerror(errno));
        return -1;
    }
    
    if ((full_bar = progress_bar(term_size.ws_col, prefix, prefix_size, suffix, suffix_size, numerator, denominator)) == NULL) {
        return -1;
    }
    printf("%s\r", full_bar);
    free(full_bar);
    free(suffix);
    free(download_bytes);
    free(download_bytes_rate);
    free(prefix);
    fflush(stdout);
    return 0;
}

static int update_cb(const char *refname, const git_oid *a, const git_oid *b, git_refspec *spec, void *data) {
	char a_str[GIT_OID_SHA1_HEXSIZE+1], b_str[GIT_OID_SHA1_HEXSIZE+1];
	git_buf remote_name = GIT_BUF_INIT;
	(void)data;

	if (git_refspec_rtransform(&remote_name, spec, refname) < 0)
		return -1;

	git_oid_fmt(b_str, b);
	b_str[GIT_OID_SHA1_HEXSIZE] = '\0';

	if (git_oid_is_zero(a)) {
		printf("[new]     %.20s %s -> %s\n", b_str, remote_name.ptr, refname);
	} else {
		git_oid_fmt(a_str, a);
		a_str[GIT_OID_SHA1_HEXSIZE] = '\0';
		printf("[updated] %.10s..%.10s %s -> %s\n", a_str, b_str, remote_name.ptr, refname);
	}
    git_buf_dispose(&remote_name);
	return 0;
}

static int sideband_progress(const char *str, int len, void *payload) {
	(void)payload; /* unused */
	printf("remote: %.*s", len, str);
	fflush(stdout);
	return 0;
}

static int fetch_progress(const git_indexer_progress *stats, void *payload) {
	progress_data *pd = (progress_data*)payload;
	pd->fetch_progress = *stats;
	return print_progress(pd);
}

struct fh_cb_ctx {
    git_repository *repo;
    git_annotated_commit **head;
};

static int fh_cb(
    const char *ref_name, const char *remote_url, const git_oid *oid, 
    unsigned int is_merge, void *payload
) {
    (void)ref_name;
    (void)remote_url;
    struct fh_cb_ctx *ctx = (struct fh_cb_ctx *)payload;

    if (!is_merge)
        return 0;

    if (*(ctx->head) != NULL) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Multiple merge heads are not supported\n");
        return 8;
    }

    if (git_annotated_commit_lookup(ctx->head, ctx->repo, oid) < 0) {
        const git_error *err = git_error_last();
		if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to lookup annotated commit: libgit2 error %d: %s\n", err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to lookup annotated commit");
        }
        return 4;
    }

    return 1;
}

static int perform_fastforward(git_repository *repo, const git_oid *target_oid, int is_unborn) {
	git_checkout_options ff_checkout_options;
    if (git_checkout_options_init(&ff_checkout_options, GIT_CHECKOUT_OPTIONS_VERSION) < 0) {
        const git_error *err = git_error_last();
		if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to initialise git checkout options: libgit2 error %d: %s\n", err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to initialise git checkout options");
        }
        return -1;
    }
	git_reference *target_ref = NULL;
	git_reference *new_target_ref = NULL;
	git_object *target = NULL;
    git_reference *head_ref = NULL;
	int result = 0;

	if (is_unborn) {
		const char *symbolic_ref;

		/* HEAD reference is unborn, lookup manually so we don't try to resolve it */
        if (git_reference_lookup(&head_ref, repo, "HEAD") != 0) {
            const git_error *err = git_error_last();
            if (err) {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to lookup HEAD ref: libgit2 error %d: %s\n", err->klass, err->message);
            } else {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to lookup HEAD ref");
            }
            return -1;
        }

		/* Grab the reference HEAD should be pointing to */
        if ((symbolic_ref = git_reference_symbolic_target(head_ref)) == NULL) {
            const git_error *err = git_error_last();
            if (err) {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to get symbolic HEAD ref: libgit2 error %d: %s\n", err->klass, err->message);
            } else {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to get symbolic HEAD ref");
            }
			goto cleanup;
		}

		/* Create our master reference on the target OID */
		if ((result = git_reference_create(&target_ref, repo, symbolic_ref, target_oid, 0, NULL)) != 0) {
            const git_error *err = git_error_last();
            if (err) {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to create master reference: libgit2 error %d: %s\n", err->klass, err->message);
            } else {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to create master reference");
            }
			goto cleanup;
		}
	} else {
		/* HEAD exists, just lookup and resolve */
        if (git_repository_head(&target_ref, repo) != 0) {
            const git_error *err = git_error_last();
            if (err) {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to get HEAD reference: libgit2 error %d: %s\n", err->klass, err->message);
            } else {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to get HEAD reference");
            }
			return -1;
		}
	}

	/* Lookup the target object */
    if ((result = git_object_lookup(&target, repo, target_oid, GIT_OBJECT_COMMIT)) != 0) {
        const git_error *err = git_error_last();
        if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to lookup OID %s: libgit2 error %d: %s\n", git_oid_tostr_s(target_oid), err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to lookup OID %s", git_oid_tostr_s(target_oid));
        }
        goto cleanup;
    }

	/* Checkout the result so the workdir is in the expected state */
	ff_checkout_options.checkout_strategy = GIT_CHECKOUT_SAFE;
    if ((result = git_checkout_tree(repo, target, &ff_checkout_options)) != 0) {
        const git_error *err = git_error_last();
        if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to checkout HEAD reference: libgit2 error %d: %s\n", err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to checkout HEAD reference");
        }
        goto cleanup;
    }

	/* Move the target reference to the target OID */
    if ((result = git_reference_set_target(&new_target_ref, target_ref, target_oid, NULL)) != 0) {
        const git_error *err = git_error_last();
        if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to move HEAD referencee: libgit2 error %d: %s\n", err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to move HEAD reference");
        }
        goto cleanup;
    }

cleanup:
    git_reference_free(head_ref);
	git_reference_free(target_ref);
	git_reference_free(new_target_ref);
	git_object_free(target);

	return result ? -1 : 0;
}

int status_cb(const char *path, unsigned int status_flags, void *payload) {
    (void)payload;
    if (status_flags == GIT_STATUS_WT_NEW || status_flags == GIT_STATUS_IGNORED) {
        printf("Removing %s\n", path);
        if(nftw(path, rmrf, 64, FTW_DEPTH | FTW_PHYS)) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Removing path %s failed: %s\n", path, strerror(errno));
            return 1;
        }
    }
    return 0;
}

uint32_t git_clone_pkg(char *base_name) {
    git_repository *cloned_repo = NULL;

	progress_data pd = {0};
    uint32_t return_code = 0;

    git_checkout_options checkout_opts;
    if (git_checkout_options_init(&checkout_opts, GIT_CHECKOUT_OPTIONS_VERSION) != 0) {
        const git_error *err = git_error_last();
        if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to initialise git checkout options: libgit2 error %d: %s\n", err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to initialise git checkout options");
        }
        return 4;
    }

    git_clone_options clone_opts;
    if (git_clone_options_init(&clone_opts, GIT_CLONE_OPTIONS_VERSION) != 0) {
        const git_error *err = git_error_last();
        if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to initialise git clone options: libgit2 error %d: %s\n", err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to initialise git clone options");
        }
        return 4;
    }

    const char url_prefix[] = ".git";
    pd.path = base_name;
    pd.operation = "Cloning";

    // we need to calculate the size of url_path
    uint32_t base_name_size;
    for ( base_name_size = 0;  base_name[ base_name_size] != '\0';  base_name_size++);
    /* note that this does not include the null terminator but sizeof(AUR_BASE_URL) does. 
    So we will get space for a terminator at the end and an extra space for the / from sizeof()
    */
    
    // calculate the url buffer size
    // should be the addition of the sizes of 2 parts: the base url and the url path
    uint32_t url_size = sizeof(AUR_BASE_URL) + base_name_size+sizeof(url_prefix);
    
    // then allocate the buffer for the url
    char *url_buffer = malloc(url_size);
    if (url_buffer == NULL) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Memory allocation error: %s\n", strerror(errno));
        return 8;
    }
   
    // then construct the url
    if (snprintf(url_buffer, url_size, "%s/%s%s", AUR_BASE_URL, base_name, url_prefix) < 0) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Couldn't concatenate string: %s\n", strerror(errno));
        return_code = 8;
        goto cleanup;
    }

    printf("Cloning %s...\n", base_name);
    
    if (git_libgit2_init() < 0) {
        const git_error *err = git_error_last();
        if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to initialise libgit2: libgit2 error %d: %s\n", err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to initialise libgit2");
        }
        return_code = 4;
        goto cleanup;
    }
    

	checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE;
	clone_opts.checkout_opts = checkout_opts;
	clone_opts.fetch_opts.callbacks.sideband_progress = sideband_progress;
	clone_opts.fetch_opts.callbacks.transfer_progress = &fetch_progress;
	clone_opts.fetch_opts.callbacks.payload = &pd;
    
    if (git_clone(&cloned_repo, url_buffer, base_name, &clone_opts) != 0) {
        const git_error *err = git_error_last();
        if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to clone %s: libgit2 error %d: %s\n", base_name, err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to clone %s", base_name);
        }
        return_code = 4;
    }
    printf("\n");

    cleanup:
        free(url_buffer);
        if (cloned_repo) {
            git_repository_free(cloned_repo);
        }
        git_libgit2_shutdown();
	    return return_code;
}

uint32_t git_pull_pkg(char *base_name, int32_t keep_existing) {
    uint32_t return_code = 0;
    git_remote *remote;
    git_reference *head = NULL;
    git_reference *upstream = NULL;
    git_buf remote_name = GIT_BUF_INIT;
    git_repository *repo = NULL;
    progress_data pd = {0};
    git_fetch_options fetch_opts;
    char *received_bs = NULL;
    int result;
	git_repository_state_t state;
	git_merge_analysis_t analysis;
	git_merge_preference_t preference;
    if (git_fetch_options_init(&fetch_opts, GIT_FETCH_OPTIONS_VERSION) != 0) {
        const git_error *err = git_error_last();
        if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to initialise git fetch options: libgit2 error %d: %s\n", err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to initialise git fetch options");
        }
        return 4;
    }

    pd.path = base_name;
    pd.operation = "Fetching";

    if (git_libgit2_init() < 0) {
        const git_error *err = git_error_last();
        if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to initialise libgit2: libgit2 error %d: %s\n", err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to initialise libgit2");
        }
        return 4;
    }

    // setup remote
    if (git_repository_open(&repo, base_name) != 0) {
        const git_error *err = git_error_last();
        if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to open repository: libgit2 error %d: %s\n", err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to open repository");
        }
        return 4;
    }
    if (git_repository_head(&head, repo) != 0) {
        const git_error *err = git_error_last();
        if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to get repository head: libgit2 error %d: %s\n", err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to get repository head");
        }
        return_code = 4;
        goto cleanup;
    }
    if (git_branch_upstream(&upstream, head) != 0) {
        const git_error *err = git_error_last();
        if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to get branch upstream: libgit2 error %d: %s\n", err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to get branch upstream");
        }
        return_code = 4;
        goto cleanup;
    }

    if (git_branch_remote_name(&remote_name, repo, git_reference_name(upstream)) != 0) {
        const git_error *err = git_error_last();
        if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to get branch remote name: libgit2 error %d: %s\n", err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to get branch remtoe");
        }
        return_code = 4;
        goto cleanup;
    }

    if (git_remote_lookup(&remote, repo, remote_name.ptr) != 0) {
        const git_error *err = git_error_last();
        if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to lookup remote: libgit2 error %d: %s\n", err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to lookup remote");
        }
        return_code = 4;
        goto cleanup;
    }

    fetch_opts.callbacks.update_refs = &update_cb;
	fetch_opts.callbacks.sideband_progress = sideband_progress;
	fetch_opts.callbacks.transfer_progress = &fetch_progress;
	fetch_opts.callbacks.payload = &pd;

    // equivalent of git clean -dfxn
    if (!keep_existing) {
        git_status_options status_opts;
        
        if (git_status_options_init(&status_opts, GIT_STATUS_OPTIONS_VERSION) != 0) {
            const git_error *err = git_error_last();
            if (err) {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to initialise git status options: libgit2 error %d: %s\n", err->klass, err->message);
            } else {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to initialise git status options");
            }
            return_code = 4;
            goto cleanup;
        }

        status_opts.show  = GIT_STATUS_SHOW_INDEX_AND_WORKDIR;
        status_opts.flags = GIT_STATUS_OPT_INCLUDE_UNTRACKED | GIT_STATUS_OPT_INCLUDE_IGNORED;

        if (git_repository_is_bare(repo)) {
            fprintf(stderr, "%s %s\n", "Cannot clean bare repository", git_repository_path(repo));
            return_code = 8;
            goto cleanup;
        }

        if (chdir(base_name) < 0) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to change directory to %s: %s", base_name, strerror(errno));
            return_code = 3;
            goto cleanup;
        }
        /* 
        For some reason libgit2 will not list files if * is in .gitignore even if the GIT_STATUS_OPT_INCLUDE_IGNORED flag is specified.
        As a workaround the rule !* is manually added.
        */
        git_ignore_add_rule(repo, "!*");
        result = git_status_foreach_ext(repo, &status_opts, status_cb, NULL);

        if (result == 1) {
            return_code = 3;
            goto cleanup;
        }
        if (result < 0) {
            const git_error *err = git_error_last();
            if (err) {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to list files to clean: libgit2 error %d: %s\n", err->klass, err->message);
            } else {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to list files to clean");
            }
            return_code = 4;
            goto cleanup;
        }
        if (chdir("..") < 0) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to traverse to parent directory: %s", strerror(errno));
            return_code = 3;
            goto cleanup;
        }
    }
    printf("Fetching %s...\n", base_name);

    if (git_remote_fetch(remote, NULL, &fetch_opts, "fetch") != 0) {
        const git_error *err = git_error_last();
        if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to fetch %s: libgit2 error %d: %s\n", base_name, err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to fetch %s", base_name);
        }
        return_code = 4;
        goto cleanup;
    }

    const git_indexer_progress *stats = git_remote_stats(remote);
    if (stats != NULL && (received_bs = byte_units(stats->received_bytes)) != NULL) {
        if (stats->local_objects > 0) {
            printf("\rReceived %u/%u objects in %s (used %u local objects)\n",
                stats->indexed_objects, stats->total_objects, received_bs, stats->local_objects);
        } else{
            printf("\rReceived %u/%u objects in %s\n",
                stats->indexed_objects, stats->total_objects, received_bs);
        }
    }

    state = git_repository_state(repo);
	if (state != GIT_REPOSITORY_STATE_NONE) {
		fprintf(stderr, "\x1b[1;31mError\x1b[0m: Repository is in unexpected state %d\n", state);
        return_code = 8;
		goto cleanup;
	}

    git_annotated_commit *merge_head = NULL;

    result = git_repository_fetchhead_foreach(repo, fh_cb, &(struct fh_cb_ctx) {repo, &merge_head});
    if (result > 1) {
        return_code = result;
        goto cleanup;
    }
    if (result < 0) {
        const git_error *err = git_error_last();
        if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to fetch head for merge analysis: libgit2 error %d: %s\n", err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to fetch head for merge analysis");
        }
        return_code = 4;
        goto cleanup;
    }
    

    if (git_merge_analysis(&analysis, &preference, repo, (const git_annotated_commit *[]){merge_head}, 1) < 0) {
        const git_error *err = git_error_last();
        if (err) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Merge analysis failed: libgit2 error %d: %s\n", err->klass, err->message);
        } else {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Merge analysis failed");
        }
        return_code = 4;
        goto cleanup;
    }

    struct {
        int key;
        const char *value;
    } analysis_lookup[] = {
        {GIT_MERGE_ANALYSIS_FASTFORWARD, "Fast Forward"},
        {GIT_MERGE_ANALYSIS_NONE, "None"},
        {GIT_MERGE_ANALYSIS_NORMAL, "Normal"},
        {GIT_MERGE_ANALYSIS_UNBORN, "Unborn"},
        {GIT_MERGE_ANALYSIS_UP_TO_DATE, "Up to date"}
    };

    for (uint64_t idx = 0; idx < ARRAY_SIZE(analysis_lookup); idx++) {
        if (analysis & analysis_lookup[idx].key) {
            printf("Git Analysis: %s\n", analysis_lookup[idx].value);
        }
    }

    if (analysis & GIT_MERGE_ANALYSIS_UP_TO_DATE) {
		goto cleanup;
	} 
    if (analysis & GIT_MERGE_ANALYSIS_UNBORN ||
	          (analysis & GIT_MERGE_ANALYSIS_FASTFORWARD &&
	          !(preference & GIT_MERGE_PREFERENCE_NO_FASTFORWARD))) {
		const git_oid *target_oid;

		/* Since this is a fast-forward, there can be only one merge head */
		target_oid = git_annotated_commit_id(merge_head);

		return_code = perform_fastforward(repo, target_oid, (analysis & GIT_MERGE_ANALYSIS_UNBORN));
        goto cleanup;
	}
    if (analysis & GIT_MERGE_ANALYSIS_NORMAL) {
		git_merge_options merge_opts;
		git_checkout_options checkout_opts;
        if (git_merge_options_init(&merge_opts, GIT_MERGE_OPTIONS_VERSION) != 0) {
            const git_error *err = git_error_last();
            if (err) {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to initialise git merge options: libgit2 error %d: %s\n", err->klass, err->message);
            } else {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to initialise git merge options");
            }
            return_code = 4;
            goto cleanup;
        }

        if (git_checkout_options_init(&checkout_opts, GIT_CHECKOUT_OPTIONS_VERSION) != 0) {
            const git_error *err = git_error_last();
            if (err) {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to initialise git checkout options: libgit2 error %d: %s\n", err->klass, err->message);
            } else {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to initialise git checkout options");
            }
            return_code = 4;
            goto cleanup;
        }

		merge_opts.flags = 0;
		merge_opts.file_flags = GIT_MERGE_FILE_STYLE_DIFF3;

		checkout_opts.checkout_strategy = GIT_CHECKOUT_FORCE|GIT_CHECKOUT_ALLOW_CONFLICTS;

		if (preference & GIT_MERGE_PREFERENCE_FASTFORWARD_ONLY) {
			fprintf(stderr, "\x1b[1;31mError\x1b[0m: Fast-forward is preferred, but only a merge is possible\n");
			return_code = 8;
            goto cleanup;
		}
        
        printf("A Merge is needed to complete git pull. Please discard changes or run git merge\n");
        return_code = 1;
	}

    cleanup:
        git_reference_free(head);
        git_reference_free(upstream);
        git_buf_dispose(&remote_name);
        if (repo) {
            git_repository_free(repo);
        }
        git_annotated_commit_free(merge_head);
        free(received_bs);
        git_remote_free(remote);
        git_libgit2_shutdown();
        return return_code;
}

uint32_t git_download_pkgs(cJSON *pkgv, uint32_t pkgc, int32_t keep_existing) {
    int return_code = 0;
    char **downloaded_bases = malloc(pkgc * sizeof(void *));
    if (downloaded_bases == NULL) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Memory allocation error: %s\n", strerror(errno));
        return 8;
    }
    uint32_t downloaded_bases_count = 0;
    cJSON *package = NULL;
    cJSON_ArrayForEach(package, pkgv) {
        cJSON *pkg_base = cJSON_GetObjectItemCaseSensitive(package, "PackageBase");
        if (!pkg_base || !(pkg_base->valuestring)) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Required data for package base name went missing.\n");
            return_code = 6;
            break;
        }
        uint8_t base_match = 0;
        for (uint32_t idx = 0; idx < downloaded_bases_count && idx < pkgc; idx++) {
            for (uint32_t str_idx = 0; pkg_base->valuestring[str_idx] == downloaded_bases[idx][str_idx]; str_idx++) {
                if (pkg_base->valuestring[str_idx] == '\0') {
                    base_match = 1;
                    break;
                }
            }
        }
        if (base_match) {
            continue;
        }
        downloaded_bases[downloaded_bases_count] = pkg_base->valuestring;
        downloaded_bases_count++;

        uid_t uid = getuid();
        struct passwd* pwd = getpwuid(uid);

        if (!pwd) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Could not get home directory\n");
            free(downloaded_bases);
            return 3;
        }
        uint32_t hdirc;
        for (hdirc = 0; pwd->pw_dir[hdirc] != '\0'; hdirc++);
        char cache_dir[] = ".cache/baurpm";
        uint32_t dirc = hdirc + sizeof(cache_dir) + 1;
        char *cache_dir_buffer = malloc(dirc);
        if (cache_dir_buffer == NULL) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Memory allocation error: %s\n", strerror(errno));
            return_code = 8;
            break;
        }

        // construct path
        if (snprintf(cache_dir_buffer, dirc, "%s/%s", pwd->pw_dir, cache_dir) < 0) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Couldn't concatenate string: %s\n", strerror(errno));
            free(cache_dir_buffer);
            return_code = 8;
            break;
        }

        if (chdir(cache_dir_buffer) < 0) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to change directory to %s: %s", cache_dir_buffer, strerror(errno));
            free(cache_dir_buffer);
            return_code = 3;
            break;
        }
        free(cache_dir_buffer);
        // extract package
        struct stat stat_info;
        int stat_status = stat(pkg_base->valuestring, &stat_info);
        if (stat_status == 0 && S_ISDIR(stat_info.st_mode)) {
            return_code = git_pull_pkg(pkg_base->valuestring, keep_existing);
        } else {
            return_code = git_clone_pkg(pkg_base->valuestring);
        }
        if (return_code) {
            break;
        }
    }
    free(downloaded_bases);
    return return_code;
}

uint32_t download_and_extract_pkgs(cJSON *pkgv, uint32_t pkgc, int32_t keep_existing) {
    int *downloaded_bases = malloc(pkgc * sizeof(int));
    uint32_t downloaded_bases_count = 0;
    const cJSON *package = NULL;
    cJSON_ArrayForEach(package, pkgv) {
        AURPkgInfo *pkg_info = new_aur_pkg_info((cJSON *) package);
        if (pkg_info == NULL) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Memory allocation error: %s\n", strerror(errno));
            return 8;
        }
        if (!(pkg_info->name) || !(pkg_info->base) || !(pkg_info->url_path) || !(pkg_info->base_id)) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Required data for package name, base, base ID or url path went missing.\n");
            aur_pkg_info_reference_free(pkg_info);
            return 6;
        }
        uint8_t base_match = 0;
        for (uint32_t idx = 0; idx < downloaded_bases_count && idx < pkgc; idx++) {
            if (pkg_info->base_id == downloaded_bases[idx]) {
                base_match = 1;
            }
        }
        if (base_match) {
            aur_pkg_info_reference_free(pkg_info);
            continue;
        }
        downloaded_bases[downloaded_bases_count] = pkg_info->base_id;
        downloaded_bases_count++;
        uint8_t different_base = 0;
        for (uint32_t idx = 0; pkg_info->name[idx] != '\0'; idx++) {
            if (pkg_info->name[idx] != pkg_info->base[idx]) {
                different_base = 1;
                break;
            }
        }
        char *base_url = NULL;
        if (different_base) {
            uint32_t slash_index = 0;
            uint32_t suffix_length = 0;
            uint32_t suffix_index = 0;
            uint8_t traversed = 0;
            for (uint32_t idx = 0;;idx++) {
                if (pkg_info->url_path[idx] == '/') {
                    slash_index = idx;
                }
                if (suffix_length) {
                    suffix_length++;
                }
                if (pkg_info->url_path[idx] == '.' && traversed && !suffix_length) {
                    suffix_index = idx;
                    suffix_length++;
                }
                if (pkg_info->url_path[idx] == '\0' && !traversed) {
                    idx = slash_index;
                    traversed = 1;
                }
                if (pkg_info->url_path[idx] == '\0' && traversed) {
                    break;
                }
            }
            uint32_t base_length;
            for (base_length = 0; pkg_info->base[base_length] != '\0'; base_length++);
            uint32_t base_url_length = slash_index+1 + base_length + suffix_length;
            base_url = malloc(base_url_length);
            // constructs url if the package has a different base.
            for (uint32_t idx = 0; idx < base_url_length; idx++) {
                if (idx <= slash_index) {
                    base_url[idx] = pkg_info->url_path[idx];
                    continue;
                }
                if (idx <= slash_index+base_length) {
                    base_url[idx] = pkg_info->base[idx-slash_index-1];
                    continue;
                }
                base_url[idx] = pkg_info->url_path[suffix_index+idx-base_length-slash_index-1];
            }
        }
        if (!base_url) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to extract url from package info\n");
            aur_pkg_info_reference_free(pkg_info);
            break;
        }
        uint8_t download_status;
        char *provider_url = base_url ? base_url : pkg_info->url_path;
        // I can free the struct here as only pointers from the original cJSON object is used
        aur_pkg_info_reference_free(pkg_info);
        // download
        char *download_path = retry_download_pkg(provider_url, &download_status);
        if (base_url) {
            free(base_url);
        }
        if (download_status) {
            if (*download_path) {
                free(download_path);
                free(downloaded_bases);
            }
            return download_status;
        }
        if (!*download_path) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API metadata went missing.\n");
            free(downloaded_bases);
            return 6;
        }
        uid_t uid = getuid();
        struct passwd* pwd = getpwuid(uid);

        if (!pwd) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Could not get home directory\n");
            free(download_path);
            free(downloaded_bases);
            return 3;
        }
        uint32_t hdirc;
        for (hdirc = 0; pwd->pw_dir[hdirc] != '\0'; hdirc++);
        char cache_dir[] = ".cache/baurpm";
        uint32_t dirc = hdirc + sizeof(cache_dir) + 1;
        char *cache_dir_buffer = malloc(dirc);
        // construct path
        snprintf(cache_dir_buffer, dirc, "%s/%s", pwd->pw_dir, cache_dir);
        chdir(cache_dir_buffer);
        free(cache_dir_buffer);
        // extract package
        int extraction_failed = extract(download_path, keep_existing);
        if (extraction_failed) {
            free(download_path);
            free(downloaded_bases);
            return extraction_failed;
        }
        free(download_path);
    }
    free(downloaded_bases);
    return 0;
}

int command_h(char *options, char *arguments[], int32_t arg_len, cJSON * _) {
    cJSON_Delete(_);
    (void)(options);

    if (arg_len) {
        for (uint64_t cmd_idx = 0; cmd_idx < ARRAY_SIZE(commands); cmd_idx++) {
            if ((arguments[0][0] & 95) == commands[cmd_idx].name) {
                char *description;
                if (commands[cmd_idx].description != NULL) {
                    description = commands[cmd_idx].description;
                } else {
                    description = "**No Description**";
                }
                printf("%c: %s\n", commands[cmd_idx].name, description);
                if (commands[cmd_idx].usage != NULL) {
                    printf(
                        "Usage:\n    baurpm -%c%s\n", commands[cmd_idx].name, commands[cmd_idx].usage
                    );
                } else {
                    printf("**No Usage**\n");
                }
                if (commands[cmd_idx].options[0] != NULL && commands[cmd_idx].options[0] != NULL) {
                    printf("Options:\n");
                    for (int32_t opt_idx = 0; commands[cmd_idx].options[opt_idx] != NULL; opt_idx++) {
                        printf("    %s\n", commands[cmd_idx].options[opt_idx]);
                    }
                } else {
                    printf("**No Options**\n");
                }
                break;
            } else if (cmd_idx == 6) {
                printf("No command by the name of %s\n", arguments[0]);
            }
            
        }
    } else {
        printf("Usage: %s [command][options] [arguments]\n", SHORT_NAME);
        printf("Executable commands:\n");
        for (uint64_t cmd_idx = 0; cmd_idx < ARRAY_SIZE(commands); cmd_idx++) {
            char *description;
            if (commands[cmd_idx].description != NULL) {
                description = commands[cmd_idx].description;
            } else {
                description = "**No Description**";
            }
            printf("-%c\t%s\n", commands[cmd_idx].name, description);
        }
        printf("use %s -H [command-name] for help with that command\n", SHORT_NAME);
    }
    return 0;

}

int command_g(char *options, char *arguments[], int32_t arg_len, cJSON *_) {
    cJSON_Delete(_);
    (void)(options);
    char **found_pkg_names;
    cJSON *response_body;
    uint8_t status;
    
    if (!arg_len) {
        fprintf(stderr, "No package names specified!\nFor usage, see %s -H for details\n", SHORT_NAME);
        return 1;
    }
    printf("Searching for \x1b[1m");
    print_string_array(arguments, arg_len);
    printf("\x1b[0m\n");
   
    response_body = find_pkg(arguments, arg_len, 0, &status);
    if (status) {
        cJSON_Delete(response_body);
        return status;
    }
    if (cJSON_IsNull(response_body)) {
        fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API metadata went missing.\n");
        return 6;
    }
    cJSON *found_packages = cJSON_GetObjectItemCaseSensitive(response_body, "results");
    if (!found_packages) {
        fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API results went missing.\n");
        cJSON_Delete(response_body);
        return 6;
    }
    AURPkgInfoArray *pkgs = new_aur_pkg_info_array(found_packages);
    if (pkgs == NULL) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Memory allocation error: %s\n", strerror(errno));
        cJSON_Delete(response_body);
        return 8;
    }
    found_pkg_names = malloc(pkgs->size * sizeof(void *));
    for (int idx = 0; idx < pkgs->size; idx++) {
        if (pkgs->items[idx]->name) {
            found_pkg_names[idx] = pkgs->items[idx]->name;
        }
    }
    if (pkgs->size == 1) {
        printf("A package called \033[1m%s\033[0m was found.\n", found_pkg_names[0]);
    } else {
        printf("Some packages called \033[1m");
        print_string_array(found_pkg_names, pkgs->size);
        printf("\033[0m were found.\n");
    }
    int return_code = 0;
    for (int idx = 0; idx < pkgs->size; idx++) {
        AURPkgInfo *pkg_info = pkgs->items[idx];
        if (!(pkg_info->name) || !(pkg_info->base) || !(pkg_info->url_path)) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Required data for package name, base or url path went missing.\n");
            return_code = 6;
            break;
        }
        printf("View information for %s? [Y/n]: ", pkg_info->name);
        char prompt[6];
        char *input_successful = fgets(prompt, sizeof(prompt), stdin);
        if (input_successful && prompt[0] != '\n' && (prompt[0] | 32) == 'n') {
            continue;
        }
        uint8_t different_base = 0;
        for (uint32_t idx = 0; pkg_info->name[idx] != '\0'; idx++) {
            if (pkg_info->name[idx] != pkg_info->base[idx]) {
                different_base = 1;
                break;
            }
        }
        if (different_base) {
            printf(
                "Note: %s has a different package base called %s.\n", 
                pkg_info->name, pkg_info->base
            );
        }
        uint32_t space_size = 0;
        cJSON *item = NULL;
        cJSON *package = cJSON_GetArrayItem(found_packages, idx);
        cJSON_ArrayForEach(item, package) {
            if (item->string) {
                uint32_t str_len;
                for (str_len = 0; item->string[str_len] != '\0'; str_len++);
                if (str_len > space_size) {
                    space_size = str_len;
                }
            }
        }
        cJSON_ArrayForEach(item, package) {
            if (item->string) {
                printf("%s:", item->string);
                uint32_t str_len;
                for (str_len = 0; item->string[str_len] != '\0'; str_len++);
                uint32_t item_spacing = space_size + 4 - str_len;
                for (uint32_t idx = 0; idx < item_spacing; idx++) {
                    printf(" ");
                }
                if (cJSON_IsArray(item)) {
                    print_cjson_string_array(item);
                    printf("\n");
                } else if (item->valuestring) {
                    printf("%s\n", item->valuestring);
                } else if (item->valueint) {
                    uint8_t is_timestamp = 0;
                    char first_sub_match[] = "FirstSubmitted";
                    char last_mod_match[] = "LastModified";
                    char ood_match[] = "OutOfDate";
                    uint32_t first_matches = 0;
                    uint32_t last_matches = 0;
                    uint32_t ood_matches = 0;
                    for (uint32_t str_idx = 0;; str_idx++) {
                        if (item->string[str_idx] == '\0') {
                            if (first_matches+1 == sizeof(first_sub_match) || last_matches+1 == sizeof(last_mod_match) || ood_matches+1 == sizeof(ood_match)) {
                                is_timestamp = 1;
                            }
                            break;
                        }
                        if (item->string[str_idx] == first_sub_match[str_idx] && last_matches == 0 && ood_matches == 0) {
                            first_matches++;
                            continue;
                        }
                        if (item->string[str_idx] == last_mod_match[str_idx] && ood_matches == 0){
                            last_matches++;
                            continue;
                        }
                        if (item->string[str_idx] == ood_match[str_idx]) {
                            ood_matches++;
                            continue;
                        }
                        break;
                    }
                    if (is_timestamp) {
                        time_t timestamp = item->valueint;
                        printf("%s", ctime(&timestamp));
                    } else {
                        printf("%d\n", item->valueint);
                    }
                } else if (item->valuedouble) {
                    printf("%lf\n", item->valuedouble);
                } else {
                    printf("\n");
                }
            }
        }
        printf("Download and view build files and PKGBUILD? [Y/n]: ");
        input_successful = fgets(prompt, sizeof(prompt), stdin);
        if (input_successful && prompt[0] != '\n' && (prompt[0] | 32) == 'n') {
            continue;
        }
        char *base_url = NULL;
        if (different_base) {
            uint32_t slash_index = 0;
            uint32_t suffix_length = 0;
            uint32_t suffix_index = 0;
            uint8_t traversed = 0;
            for (uint32_t idx = 0;;idx++) {
                if (pkg_info->url_path[idx] == '/') {
                    slash_index = idx;
                }
                if (suffix_length) {
                    suffix_length++;
                }
                if (pkg_info->url_path[idx] == '.' && traversed && !suffix_length) {
                    suffix_index = idx;
                    suffix_length++;
                }
                if (pkg_info->url_path[idx] == '\0' && !traversed) {
                    idx = slash_index;
                    traversed = 1;
                }
                if (pkg_info->url_path[idx] == '\0' && traversed) {
                    break;
                }
            }
            uint32_t base_length;
            for (base_length = 0; pkg_info->base[base_length] != '\0'; base_length++);
            uint32_t base_url_length = slash_index+1 + base_length + suffix_length;
            base_url = malloc(base_url_length);
            for (uint32_t idx = 0; idx < base_url_length; idx++) {
                if (idx <= slash_index) {
                    base_url[idx] = pkg_info->url_path[idx];
                    continue;
                }
                if (idx <= slash_index+base_length) {
                    base_url[idx] = pkg_info->base[idx-slash_index-1];
                    continue;
                }
                base_url[idx] = pkg_info->url_path[suffix_index+idx-base_length-slash_index-1];
            }
        }
        if (!base_url) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to extract url from package info\n");
            return_code = 1;
            break;
        }
        uint8_t download_status;
        char *provider_url = base_url ? base_url : pkg_info->url_path;
        char *download_path = retry_download_pkg(provider_url, &download_status);
        if (base_url) {
            free(base_url);
        }
        if (download_status) {
            if (*download_path) {
                free(download_path);
            }
            return_code = download_status;
            break;
        }
        if (!*download_path) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API metadata went missing.\n");
            return_code = 6;
            break;
        }
        uid_t uid = getuid();
        struct passwd* pwd = getpwuid(uid);

        if (!pwd) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Could not get home directory");
            free(download_path);
            return_code = 3;
            break;
        }
        uint32_t hdirc;
        for (hdirc = 0; pwd->pw_dir[hdirc] != '\0'; hdirc++);
        char cache_dir[] = ".cache/baurpm";
        uint32_t dirc = hdirc + sizeof(cache_dir) + 1;
        char *cache_dir_buffer = malloc(dirc);
        snprintf(cache_dir_buffer, dirc, "%s/%s", pwd->pw_dir, cache_dir);
        chdir(cache_dir_buffer);
        free(cache_dir_buffer);
        int extraction_failed = extract(download_path, 0);
        free(download_path);
        if (extraction_failed) {
            return_code = extraction_failed;
            break;
        }
        
        printf("Build files for \033[1m%s\033[0m are:\n     ", pkg_info->base);
        DIR *dir = opendir(pkg_info->base);
        if (!dir) { 
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: could not list directory\n"); 
            return_code = 4;
            break;
        }
        struct dirent *dir_item;
        while ((dir_item = readdir(dir)) != NULL) {
            if (!(
                (dir_item->d_name[0] == '.' && dir_item->d_name[1] == '\0') 
                || 
                (dir_item->d_name[0] == '.' && dir_item->d_name[1] == '.' && dir_item->d_name[2] == '\0')
            )) {
                printf("%s ", dir_item->d_name);    
            }
        }
        printf("\n");
        closedir(dir);
        printf("See \033[1m~/.cache/baurpm/%s\033[0m for more information.\n", pkg_info->base);
        printf("Press Enter to continue and view PKGBUILD");
        getchar();
        chdir(pkg_info->base);
        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to fork process: %s\n", strerror(errno));
            continue;
        }
        if (pid == 0) {
            char *argv[] = {
                "less", "PKGBUILD", NULL
            };
            execvp("less", argv);
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: less command failed: %s\n", strerror(errno));
            _exit(127);
        }
        int32_t less_status;
        if (waitpid(pid, &less_status, 0) < 0) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed waiting for less command: %s\n", strerror(errno));
            continue;
        }
        int less_failed = WEXITSTATUS(less_status);
        if (WIFSIGNALED(less_status)) {
            if (WTERMSIG(less_status) == SIGINT) {
                fprintf(stderr, "\x1b[1;33mWarning\x1b[0m: less command stopped by user\n");
            } else {
                fprintf(
                    stderr, "\x1b[1;33mWarning\x1b[0m: less command exited due to signal %d: %s\n", 
                    WTERMSIG(less_status), strsignal(WTERMSIG(less_status)));
            }
            continue;
        }
        if (less_failed) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: less command failed with exit code %d\n", less_failed);
        }
    }
    free(found_pkg_names);
    aur_pkg_info_array_free(pkgs);
    cJSON_Delete(response_body);
    return return_code;
}

int command_i(char *options, char *arguments[], int32_t arg_len, cJSON *package_data) {
    uint8_t skip_missing = 0;
    uint8_t skip_review = 0;
    int32_t keep_existing = 0;
    for (uint32_t idx = 0; options[idx] != '\0'; idx++) {
        switch (options[idx]) {
            case 'f':
                skip_missing = 1;
                break;
            case 'n':
                skip_review = 1;
                break;
            case 'd':
                keep_existing = 1;
        }
    }
    int32_t to_ignore_len = 0;
    char **to_ignore = malloc(sizeof(void *)*arg_len);
    for (int32_t idx = 0; idx < arg_len; idx++) {
        if (arguments[idx][0] == '-') {
            to_ignore[to_ignore_len] = arguments[idx];
            to_ignore_len++;
        }
    }
    int32_t to_search_len = 0;
    char **to_search = malloc(sizeof(void *)*arg_len);
    for (int32_t idx = 0; idx < arg_len; idx++) {
        if (arguments[idx][0] != '-') {
            int32_t ignore_match = 0;
            for (int32_t inner_idx = 0; inner_idx < to_ignore_len; inner_idx++) {
                for (uint32_t str_idx = 0; arguments[idx][str_idx] == to_ignore[inner_idx][str_idx+1]; str_idx++) {
                    if (to_ignore[inner_idx][str_idx+1] == '\0') {
                        ignore_match = 1;
                        break;
                    }
                }
            }
            if (ignore_match) {
                printf("Skipping %s\n", arguments[idx]);
            } else {
                to_search[to_search_len] = arguments[idx];
                to_search_len++;
            }
        }
    }
    if (!to_search_len) {
        fprintf(stderr, "No package names specified!\nFor usage, see %s -H for details\n", SHORT_NAME);
        free(to_search);
        if (cJSON_IsNull(package_data)) {
            cJSON_Delete(package_data);
        }
        free(to_ignore);
        return 1;
    }
    cJSON *response_body = NULL;
    cJSON *found_packages = NULL;
    uint8_t status;
    if (!cJSON_IsNull(package_data)) {
        printf("Using pre-fetched package data...\n");
        free(to_search);
        found_packages = package_data;
    } else {
        printf("Searching for \x1b[1m");
        print_string_array(to_search, to_search_len);
        printf("\x1b[0m\n");
        /*
        find_pkg Status Codes:
        0: OK
        2: Package not found
        3: cURL init failed
        4: cURL perform error 
        5: HTTP error
        6: AURWebRTC error
        7: HTTP response content type was not 'application/json'
        8: cJSON parsing error
        9: JSON key error
        */
        response_body = find_pkg(to_search, to_search_len, skip_missing, &status);
        free(to_search);
        if (status) {
            if (cJSON_IsNull(package_data)) {
                cJSON_Delete(package_data);
            }
            cJSON_Delete(response_body);
            free(to_ignore);
            return status;
        }
        if (cJSON_IsNull(response_body)) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API metadata went missing.\n");
            if (cJSON_IsNull(package_data)) {
                cJSON_Delete(package_data);
            }
            free(to_ignore);
            return 6;
        }
        found_packages = cJSON_GetObjectItemCaseSensitive(response_body, "results");
    }
    if (!found_packages) {
        fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API results went missing.\n");
        cJSON_Delete(response_body);
        if (cJSON_IsNull(package_data)) {
            cJSON_Delete(package_data);
        }
        free(to_ignore);
        return 6;
    }
    if (!cJSON_GetArraySize(found_packages)) {
        cJSON_Delete(response_body);
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: No packages to install, exiting...\n");
        free(to_ignore);
        return 8;
    }
    AURPkgInfoArray *pkgs = new_aur_pkg_info_array(found_packages);
    if (pkgs == NULL) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Memory allocation error: %s\n", strerror(errno));
        cJSON_Delete(response_body);
        return 8;
    }
    char **found_pkg_names = malloc(pkgs->size * sizeof(void *));
    for (int idx = 0; idx < pkgs->size; idx++) {
        if (pkgs->items[idx]->name) {
            found_pkg_names[idx] = pkgs->items[idx]->name;
        }
    }
    char *input_successful = NULL;
    char prompt[6];
    if (cJSON_IsNull(package_data)) {
        cJSON_Delete(package_data);
        if (pkgs->size == 1) {
            printf("A package called \033[1m%s\033[0m was found.\nMake and install the package? [Y/n]: ", found_pkg_names[0]);
        } else {
            printf("Some packages called \033[1m");
            print_string_array(found_pkg_names, pkgs->size);
            printf("\033[0m were found.\nMake and install the packages? [Y/n]: ");
        }
        input_successful = fgets(prompt, sizeof(prompt), stdin);
        if (input_successful && prompt[0] != '\n' && (prompt[0] | 32) == 'n') {
            printf("Installation aborted\n");
            free(found_pkg_names);
            aur_pkg_info_array_free(pkgs);
            cJSON_Delete(response_body);
            free(to_ignore);
            return 0;
        }
    }
    printf("Downloading packages...\n");
    // uint32_t download_and_extraction_failed = download_and_extract_pkgs(found_packages, found_pkg_arrc, keep_existing);
    uint32_t download_and_extraction_failed = git_download_pkgs(found_packages, pkgs->size, keep_existing);
    if (download_and_extraction_failed) {
        free(found_pkg_names);
        aur_pkg_info_array_free(pkgs);
        cJSON_Delete(response_body);
        free(to_ignore);
        return download_and_extraction_failed;
    }
    int *fetched_bases = malloc(pkgs->size * sizeof(int));
    int fetched_bases_count = 0;
    for (int pkg_idx = 0; pkg_idx < pkgs->size; pkg_idx++) {
        AURPkgInfo *pkg_info = pkgs->items[pkg_idx];
        if (!(pkg_info->name) || !(pkg_info->base) || !(pkg_info->base_id)) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Required data for package name, base or base ID went missing.\n");
            free(found_pkg_names);
            aur_pkg_info_array_free(pkgs);
            cJSON_Delete(response_body);
            free(to_ignore);
            return 6;
        }
        uint8_t different_base = 0;
        for (uint32_t idx = 0; pkg_info->name[idx] != '\0'; idx++) {
            if (pkg_info->name[idx] != pkg_info->base[idx]) {
                different_base = 1;
                break;
            }
        }
        if (different_base) {
            printf(
                "Note: %s has a different package base called %s.\n", 
                pkg_info->name, pkg_info->base
            );
        }
        uint8_t base_match = 0;
        for (int idx = 0; idx < fetched_bases_count && idx < pkgs->size; idx++) {
            if (pkg_info->base_id == fetched_bases[idx]) {
                base_match = 1;
            }
        }
        if (base_match) {
            continue;
        }
        fetched_bases[fetched_bases_count] = pkg_info->base_id;
        fetched_bases_count++;
    }
    if (!skip_review) {
        int *viewed_bases = malloc((fetched_bases_count) * sizeof(int));
        int viewed_bases_count = 0;
        for (int pkg_idx = 0; pkg_idx < pkgs->size; pkg_idx++) {
            AURPkgInfo *pkg_info = pkgs->items[pkg_idx];
            if (!(pkg_info->name) || !(pkg_info->base) || !(pkg_info->base_id)) {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Required data for package name, base or base ID went missing.\n");
                free(viewed_bases);
                free(found_pkg_names);
                aur_pkg_info_array_free(pkgs);
                cJSON_Delete(response_body);
                free(to_ignore);
                return 6;
            }
            uint8_t base_match = 0;
            for (int idx = 0; idx < viewed_bases_count && idx < pkgs->size; idx++) {
                if (pkg_info->base_id == fetched_bases[idx]) {
                    base_match = 1;
                }
            }
            if (base_match) {
                continue;
            }
            viewed_bases[viewed_bases_count] = pkg_info->base_id;
            viewed_bases_count++;
            printf("Build files for \033[1m%s\033[0m are:\n     ", pkg_info->base);
            DIR *dir = opendir(pkg_info->base);
            if (!dir) { 
                printf("\n");
                fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: could not list directory\n"); 
                free(viewed_bases);
                free(found_pkg_names);
                aur_pkg_info_array_free(pkgs);
                cJSON_Delete(response_body);
                free(to_ignore);
                return 4;
            }
            struct dirent *dir_item;
            while ((dir_item = readdir(dir)) != NULL) {
                if (!(
                    (dir_item->d_name[0] == '.' && dir_item->d_name[1] == '\0') 
                    || 
                    (dir_item->d_name[0] == '.' && dir_item->d_name[1] == '.' && dir_item->d_name[2] == '\0')
                )) {
                    printf("%s ", dir_item->d_name);    
                }
            }
            printf("\n");
            closedir(dir);
            printf("See \033[1m~/.cache/baurpm/%s\033[0m for more information.\n", pkg_info->base);
            printf("Press Enter to continue and view PKGBUILD");
            getchar();
            printf("\n");
            chdir(pkg_info->base);
            pid_t pid = fork();
            if (pid < 0) {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to fork process: %s\n", strerror(errno));
            }
            if (pid == 0) {
                char *argv[] = {
                    "less", "PKGBUILD", NULL
                };
                execvp("less", argv);
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: less command failed: %s\n", strerror(errno));
                _exit(127);
            }
            int32_t less_status;
            if (waitpid(pid, &less_status, 0) < 0) {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed waiting for less command: %s\n", strerror(errno));
            }
            int less_failed = WEXITSTATUS(less_status);
            if (WIFSIGNALED(less_status)) {
                if (WTERMSIG(less_status) == SIGINT) {
                    fprintf(stderr, "\x1b[1;33mWarning\x1b[0m: less command stopped by user\n");
                } else {
                    fprintf(
                        stderr, "\x1b[1;33mWarning\x1b[0m: less command exited due to signal %d: %s\n", 
                        WTERMSIG(less_status), strsignal(WTERMSIG(less_status)));
                }
            }
            if (less_failed) {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: less command failed with exit code %d\n", less_failed);
            }
            chdir("..");
        }
        free(viewed_bases);
        printf("Continue Installation? [Y/n]: ");
        input_successful = fgets(prompt, sizeof(prompt), stdin);
        if (input_successful && prompt[0] != '\n' && (prompt[0] | 32) == 'n') {
            printf("Installation aborted\n");
            aur_pkg_info_array_free(pkgs);
            free(found_pkg_names);
            free(fetched_bases);
            cJSON_Delete(response_body);
            free(to_ignore);
            return 0;
        }
    }
    printf("Checking dependencies...\n");
    printf(
        "Note: this version doesn't support nested aur dependencies. "
        "The build process will fail if a package has aur dependencies more than 1 dependency layer deep.\n"
    );
    printf(
        "WARNING: this version doesn't check for dependency version conflicts. "
        "Please make sure all your packages are up to date or face the risk of a partial upgrade\n"
    );
    char **base_dependencies = NULL;
    uint32_t base_dependencies_amount = 0;
    for (int pkg_idx = 0; pkg_idx < pkgs->size; pkg_idx++) {
        AURPkgInfo *pkg_info = pkgs->items[pkg_idx];
        if (!(pkg_info->name) || !(pkg_info->base) || !(pkg_info->base_id)) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Required data for package name, base or base ID went missing.\n");
            free(found_pkg_names);
            aur_pkg_info_array_free(pkgs);
            cJSON_Delete(response_body);
            free(fetched_bases);
            free(to_ignore);
            
            return 6;
        }
        uint8_t base_match = 0;
        for (int idx = 0; idx < fetched_bases_count && idx < pkgs->size; idx++) {
            if (pkg_info->base_id == fetched_bases[idx]) {
                base_match = 1;
            }
        }
        if (base_match) {
            continue;
        }
        uint8_t different_base = 0;
        for (uint32_t idx = 0; pkg_info->name[idx] != '\0'; idx++) {
            if (pkg_info->name[idx] != pkg_info->base[idx]) {
                different_base = 1;
                break;
            }
        }
        if (different_base) {
            chdir(pkg_info->base);
            struct stat stat_info;
            int stat_status = stat(".SRCINFO", &stat_info);
            if (stat_status) {
                printf("Generating information on dependencies for package base \x1b[1m%s\x1b[0m...\n", pkg_info->base);
                pid_t pid = fork();
                if (pid < 0) {
                    fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Error forking process: %s\n", strerror(errno));
                    free(found_pkg_names);
                    aur_pkg_info_array_free(pkgs);
                    cJSON_Delete(response_body);
                    free(fetched_bases);
                    free(to_ignore);
                    return 4;
                }
                if (pid == 0) {
                    int fd = open(".SRCINFO", O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if (fd == -1) {
                        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to generate .SRCINFO: %s\n", strerror(errno));
                        _exit(127);
                    }
                    dup2(fd, STDOUT_FILENO);
                    dup2(fd, STDERR_FILENO);
                    close(fd);
                    char *argv[] = {
                        "makepkg", "--printsrcinfo", NULL
                    };
                    execvp("makepkg", argv);
                    fprintf(stderr, "\x1b[1;31mError\x1b[0m: Makepkg command failed to run: %s\n", strerror(errno));
                    _exit(127);
                }
                int32_t srcinfo_status_info;
                if (waitpid(pid, &srcinfo_status_info, 0) < 0) {
                    fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Error waiting for makepkg command: %s\n", strerror(errno));
                    free(found_pkg_names);
                    aur_pkg_info_array_free(pkgs);
                    cJSON_Delete(response_body);
                    free(fetched_bases);
                    free(to_ignore);
                    return 4;
                }
                int srcinfo_status = WEXITSTATUS(srcinfo_status_info);
                if (srcinfo_status_info == -1) {
                    fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: waitpid error -1\n");
                    free(found_pkg_names);
                    aur_pkg_info_array_free(pkgs);
                    cJSON_Delete(response_body);
                    free(fetched_bases);
                    free(to_ignore);
                    return 4;
                    
                }
                if (WIFSIGNALED(srcinfo_status_info)) {
                    fprintf(
                        stderr, "\x1b[1;33mStopping\x1b[0m: makepkg exited due to signal %d: %s\n", 
                        WTERMSIG(srcinfo_status_info), strsignal(WTERMSIG(srcinfo_status_info)));
                    free(found_pkg_names);
                    aur_pkg_info_array_free(pkgs);
                    cJSON_Delete(response_body);
                    free(fetched_bases);
                    free(to_ignore);
                    return 128+WTERMSIG(srcinfo_status_info);
                }
                if (srcinfo_status) {
                    fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: makepkg error %d\n", srcinfo_status);
                    free(found_pkg_names);
                    aur_pkg_info_array_free(pkgs);
                    cJSON_Delete(response_body);
                    free(fetched_bases);
                    free(to_ignore);
                    return 32+srcinfo_status;
                }
            }

            int srcinfo_closed;
            FILE *srcinfo_file;
            char srcinfo[PATH_MAX];

            srcinfo_file = fopen(".SRCINFO", "r");
            if (srcinfo_file == NULL) {
                fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: error opening .SRCINFO\n");
                free(found_pkg_names);
                aur_pkg_info_array_free(pkgs);
                cJSON_Delete(response_body);
                free(fetched_bases);
                free(to_ignore);
                return 3;
            }
            size_t srcinfo_size = fread(srcinfo, sizeof(char), PATH_MAX, srcinfo_file);

            srcinfo_closed = fclose(srcinfo_file);
            if (srcinfo_closed == -1) {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Couldn't close .SRCINFO file\n");
            }

            char *dep_content = malloc(srcinfo_size);
            if (base_dependencies == NULL) {
                base_dependencies = malloc(PATH_MAX * pkgs->size * sizeof(void *));
            }
            char line_match[] = "\n\tdepends = ";
            uint8_t record_dependency = 0;
            uint16_t dep_idx = 0;
            uint16_t line_index = 0;
            for (uint16_t idx = 0; idx < srcinfo_size; idx++) {
                if ((!record_dependency) && srcinfo[idx] == line_match[line_index]) {
                    line_index++;
                    continue;
                }
                if (line_match[line_index] == '\0') {
                    record_dependency = 1;
                }
                line_index = 0;
                if (record_dependency) {
                    if (srcinfo[idx] == '\n') {
                        dep_content[dep_idx] = '\0';
                        char *dep_content_copy = malloc(dep_idx+1);
                        uint8_t already_in = 0;
                        for (uint32_t dependsi = 0; dependsi < base_dependencies_amount; dependsi++) {
                            for (uint32_t str_idx = 0; base_dependencies[dependsi][str_idx] == dep_content[str_idx]; str_idx++) {
                                if (dep_content[str_idx] == '\0') {
                                    already_in = 1;
                                    break;
                                }
                            }
                        }
                        record_dependency = 0;
                        line_index++;
                        if (already_in) {
                            dep_idx = 0;
                            free(dep_content_copy);
                            continue;
                        }
                        snprintf(dep_content_copy, dep_idx+1, "%s", dep_content);
                        base_dependencies[base_dependencies_amount] = dep_content_copy;
                        base_dependencies_amount++;
                        dep_idx = 0;
                        continue;
                    }
                    dep_content[dep_idx] = srcinfo[idx];

                    dep_idx++;
                }
            }
            free(dep_content);
            chdir("..");
        }
    }
    free(fetched_bases);
    // for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
    //     if (idx) {
    //         printf(", ");
    //     }
    //     printf("%s", base_dependencies[idx]);
    // }
    // printf("\n");
    uint32_t max_depends = base_dependencies_amount;
    for (int pkg_idx = 0; pkg_idx < pkgs->size; pkg_idx++) {
        AURPkgInfo *pkg_info = pkgs->items[pkg_idx];
        if (pkg_info->depends != NULL && pkg_info->depends_size > 0) {
            max_depends += pkg_info->depends_size;
        }
        if (pkg_info->make_depends != NULL && pkg_info->make_depends_size > 0) {
            max_depends += pkg_info->make_depends_size;
        }

    }
    // printf("%u\n", max_depends);
    char **all_depends = malloc(max_depends * sizeof(void *));
    uint32_t actual_depends = base_dependencies_amount;
    for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
        all_depends[idx] = base_dependencies[idx];
    }
    for (int pkg_idx = 0; pkg_idx < pkgs->size; pkg_idx++) {
        AURPkgInfo *pkg_info = pkgs->items[pkg_idx];
        if (pkg_info->depends != NULL) {
            for (int dep_idx = 0; dep_idx < pkg_info->depends_size; dep_idx++) {
                if (pkg_info->depends[dep_idx] == NULL) {
                    continue;
                }
                uint8_t already_listed = 0;
                for (uint32_t dependsi = 0; dependsi < actual_depends; dependsi++) {
                    for (uint32_t str_idx = 0; all_depends[dependsi][str_idx] == pkg_info->depends[dep_idx][str_idx]; str_idx++) {
                        if (pkg_info->depends[dep_idx][str_idx] == '\0') {
                            already_listed = 1;
                            break;
                        }
                    }
                }
                if (!already_listed) {
                    for (uint32_t idx = 0; pkg_info->depends[dep_idx][idx] != '\0'; idx++) {
                        if (pkg_info->depends[dep_idx][idx] == '<' || pkg_info->depends[dep_idx][idx] == '>' || pkg_info->depends[dep_idx][idx] == '=') {
                            pkg_info->depends[dep_idx][idx] = '\0';
                        }
                    }
                    int32_t ignore_match = 0;
                    for (int32_t idx = 0; idx < to_ignore_len; idx++) {
                        for (uint32_t str_idx = 0; pkg_info->depends[dep_idx][str_idx] == to_ignore[idx][str_idx+1]; str_idx++) {
                            if (to_ignore[idx][str_idx+1] == '\0') {
                                ignore_match = 1;
                                break;
                            }
                        }
                    }
                    if (ignore_match) {
                        printf("Skipping %s\n", pkg_info->depends[dep_idx]);
                    } else {
                        all_depends[actual_depends] = pkg_info->depends[dep_idx];
                        actual_depends++;
                    }
                }
            }
        }
        if (pkg_info->make_depends != NULL) {
            for (int dep_idx = 0; dep_idx < pkg_info->make_depends_size; dep_idx++) {
                if (pkg_info->make_depends[dep_idx] == NULL) {
                    continue;
                }
                uint8_t already_listed = 0;
                for (uint32_t dependsi = 0; dependsi < actual_depends; dependsi++) {
                    for (uint32_t str_idx = 0; all_depends[dependsi][str_idx] == pkg_info->make_depends[dep_idx][str_idx]; str_idx++) {
                        if (pkg_info->make_depends[dep_idx][str_idx] == '\0') {
                            already_listed = 1;
                            break;
                        }
                    }
                }
                if (!already_listed) {
                    for (uint32_t idx = 0; pkg_info->make_depends[dep_idx][idx] != '\0'; idx++) {
                        if (pkg_info->make_depends[dep_idx][idx] == '<' || pkg_info->make_depends[dep_idx][idx] == '>' || pkg_info->make_depends[dep_idx][idx] == '=') {
                            pkg_info->make_depends[dep_idx][idx] = '\0';
                        }
                    }
                    int32_t ignore_match = 0;
                    for (int32_t idx = 0; idx < to_ignore_len; idx++) {
                        for (uint32_t str_idx = 0; pkg_info->make_depends[dep_idx][str_idx] == to_ignore[idx][str_idx+1]; str_idx++) {
                            if (to_ignore[idx][str_idx+1] == '\0') {
                                ignore_match = 1;
                                break;
                            }
                        }
                    }
                    if (ignore_match) {
                        printf("Skipping %s\n", pkg_info->make_depends[dep_idx]);
                    } else {
                        all_depends[actual_depends] = pkg_info->make_depends[dep_idx];
                        actual_depends++;
                    }
                }
            }
        }
    }
    free(to_ignore);
    // for (uint32_t idx = 0; idx < actual_depends; idx++) {
    //     if (idx) {
    //         printf(", ");
    //     }
    //     printf("%s", all_depends[idx]);
    // }
    // printf("\n");
    char *install_cmd_prefix[] = {"sudo", "pacman", "-U", NULL};
    if (actual_depends) {
        printf("Fetching dependencies...\n");
        cJSON *depends_response_body = find_pkg(all_depends, actual_depends, 1, &status);
        free(all_depends);
        if (status) {
            cJSON_Delete(depends_response_body);
            aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
            free(found_pkg_names);
            aur_pkg_info_array_free(pkgs);
            cJSON_Delete(response_body);
            return status;
        }
        if (cJSON_IsNull(depends_response_body)) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API metadata went missing.\n");
            aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
            free(found_pkg_names);
            aur_pkg_info_array_free(pkgs);
            cJSON_Delete(response_body);
            return 6;
        }
        cJSON *found_dependencies = cJSON_GetObjectItemCaseSensitive(depends_response_body, "results");
        if (!found_dependencies) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API results went missing.\n");
            cJSON_Delete(depends_response_body);
            aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
            free(found_pkg_names);
            aur_pkg_info_array_free(pkgs);
            cJSON_Delete(response_body);
            return 6;
        }
        alpm_errno_t err;
        alpm_handle_t * handle = alpm_initialize("/", PACMAN_DB_PATH, &err);
        if (handle == NULL) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: ALPM Error %d: %s\n", err, alpm_strerror(err));
            return 4;
        }
        alpm_db_t * local_db = alpm_get_localdb(handle);
        // alpm_list_t * packages = alpm_db_get_pkgcache(local_db);
        
        cJSON *found_dependency = NULL;
        // printf("%d\n", cJSON_GetArraySize(found_dependencies));
        cJSON *required_dependencies = cJSON_CreateArray();
        uint32_t required_dependencies_count = 0;
        cJSON_ArrayForEach(found_dependency, found_dependencies) {
            cJSON *dep_base_id = cJSON_GetObjectItemCaseSensitive(found_dependency, "PackageBaseID");
            cJSON *pkg_name = cJSON_GetObjectItemCaseSensitive(found_dependency, "Name");
            cJSON *pkg_version = cJSON_GetObjectItemCaseSensitive(found_dependency, "Version");
            if ((!dep_base_id) || (!cJSON_IsNumber(dep_base_id))) {
                continue;
            }
            uint8_t base_match = 0;
            cJSON *package = NULL;
            cJSON_ArrayForEach(package, found_packages) {
                cJSON *pkg_base_id = cJSON_GetObjectItemCaseSensitive(package, "PackageBaseID");
                if ((!pkg_base_id) || (!cJSON_IsNumber(pkg_base_id))) {
                    continue;
                }
                if (dep_base_id->valueint == pkg_base_id->valueint) {
                    base_match = 1;
                }
            }
            if (base_match) {
                continue;
            }
            uint32_t up_to_date = 0;
            alpm_pkg_t *installed_pkg = alpm_db_get_pkg(local_db, pkg_name->valuestring);
            if (installed_pkg) {
                const char *installed_pkg_version = alpm_pkg_get_version(installed_pkg);
                for (uint32_t idx = 0; pkg_version->valuestring[idx] == installed_pkg_version[idx]; idx++) {
                    if (pkg_version->valuestring[idx] == '\0') {
                        up_to_date = 1;
                        break;
                    }
                }
            }
            if (up_to_date) {
                continue;
            }
            required_dependencies_count++;
            cJSON_AddItemReferenceToArray(required_dependencies, found_dependency);
        }
        alpm_release(handle);
        if (required_dependencies_count > 0) {
            printf("Downloading dependencies...\n");
            // download_and_extraction_failed = download_and_extract_pkgs(required_dependencies, required_dependencies_count, keep_existing);
            download_and_extraction_failed = git_download_pkgs(required_dependencies, required_dependencies_count, keep_existing);
            if (download_and_extraction_failed) {
                aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
                free(found_pkg_names);
                cJSON_Delete(required_dependencies);
                cJSON_Delete(depends_response_body);
                aur_pkg_info_array_free(pkgs);
                cJSON_Delete(response_body);
                return download_and_extraction_failed;
            }
        }
        char **built_dep_bases = malloc((required_dependencies_count) * sizeof(void *));
        int built_dep_bases_count = 0;
        uint32_t dependency_install_count = 0;
        uint32_t dep_install_args_len = 0;
        uint32_t arg_max = sysconf(_SC_PAGE_SIZE)*sizeof(int)*CHAR_BIT-1;
        char **dep_install_args = malloc(sizeof(void *)*arg_max);
        for (int32_t pfx = 0; install_cmd_prefix[pfx] != NULL; pfx++) {
            dep_install_args[dep_install_args_len] = install_cmd_prefix[pfx];
            dep_install_args_len++;
        }
        uint32_t non_dyn_dep_install_args = dep_install_args_len;
        cJSON *package = NULL;
        cJSON_ArrayForEach(package, required_dependencies) {
            cJSON *pkg_base = cJSON_GetObjectItemCaseSensitive(package, "PackageBase");
            uint8_t base_match = 0;
            for (int idx = 0; idx < built_dep_bases_count && idx < pkgs->size; idx++) {
                for (uint32_t str_idx = 0; pkg_base->valuestring[str_idx] == built_dep_bases[idx][str_idx]; str_idx++) {
                    if (pkg_base->valuestring[str_idx] == '\0') {
                        base_match = 1;
                        break;
                    }
                }
            }
            if (base_match) {
                continue;
            }
            built_dep_bases[built_dep_bases_count] = pkg_base->valuestring;
            built_dep_bases_count++;
            if (required_dependencies_count > 1) {
                printf("Making Dependency %d/%d \x1b[1m%s\x1b[0m\n", built_dep_bases_count, required_dependencies_count, pkg_base->valuestring);
            } else {
                printf("Making Dependency \x1b[1m%s\x1b[0m\n", pkg_base->valuestring);
            }
            chdir(pkg_base->valuestring);
            pid_t pid = fork();
            if (pid < 0) {
                fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Error forking process: %s\n", strerror(errno));
                aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
                for (uint32_t idx = non_dyn_dep_install_args; idx < dep_install_args_len; idx++){
                    free(dep_install_args[idx]);
                }
                free(dep_install_args);
                free(built_dep_bases);
                free(found_pkg_names);
                cJSON_Delete(required_dependencies);
                cJSON_Delete(depends_response_body);
                aur_pkg_info_array_free(pkgs);
                cJSON_Delete(response_body);
                return 4;
            }
            if (pid == 0) {
                char *argv[] = {
                    "makepkg", "-sf", NULL
                };
                execvp("makepkg", argv);
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Makepkg command failed to run: %s\n", strerror(errno));
                _exit(127);
            }
            int32_t makepkg_status_info;
            if (waitpid(pid, &makepkg_status_info, 0) < 0) {
                fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Error waiting for makepkg command: %s\n", strerror(errno));
                aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
                free(built_dep_bases);
                free(found_pkg_names);
                cJSON_Delete(required_dependencies);
                cJSON_Delete(depends_response_body);
                aur_pkg_info_array_free(pkgs);
                cJSON_Delete(response_body);
                for (uint32_t idx = non_dyn_dep_install_args; idx < dep_install_args_len; idx++){
                    free(dep_install_args[idx]);
                }
                free(dep_install_args);
                return 4;
            }
            int makepkg_status = WEXITSTATUS(makepkg_status_info);
            if (makepkg_status || WIFSIGNALED(makepkg_status_info)) {
                int return_code = 0;
                if (WIFSIGNALED(makepkg_status_info)) {
                    if (WTERMSIG(makepkg_status_info) == SIGINT) {
                        fprintf(stderr, "\x1b[1;33mStopping\x1b[0m: Makepkg process stopped by user\n");
                    } else {
                        fprintf(stderr, "\x1b[1;33mStopping\x1b[0m: Makepkg process exited due to signal %d: %s\n", WTERMSIG(makepkg_status_info), strsignal(WTERMSIG(makepkg_status_info)));
                    }
                    return_code = 128 + WTERMSIG(makepkg_status_info);
                }
                if (makepkg_status) {
                    fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: makepkg error %d\n", makepkg_status);
                    return_code = 32+ makepkg_status;
                }
                aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
                for (uint32_t idx = non_dyn_dep_install_args; idx < dep_install_args_len; idx++){
                    free(dep_install_args[idx]);
                }
                free(dep_install_args);
                free(built_dep_bases);
                free(found_pkg_names);
                cJSON_Delete(required_dependencies);
                cJSON_Delete(depends_response_body);
                aur_pkg_info_array_free(pkgs);
                cJSON_Delete(response_body);
                return return_code;
            }
            DIR *dir = opendir("./");
            if (!dir) { 
                printf("\n");
                fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Could not list directory\n"); 
                for (uint32_t idx = non_dyn_dep_install_args; idx < dep_install_args_len; idx++){
                    free(dep_install_args[idx]);
                }
                free(dep_install_args);
                aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
                free(built_dep_bases);
                free(found_pkg_names);
                cJSON_Delete(required_dependencies);
                cJSON_Delete(depends_response_body);
                aur_pkg_info_array_free(pkgs);
                cJSON_Delete(response_body);
                return 4;
            }
            struct dirent *dir_item;
            while ((dir_item = readdir(dir)) != NULL) {
                if (!(
                    (dir_item->d_name[0] == '.' && dir_item->d_name[1] == '\0') 
                    || 
                    (dir_item->d_name[0] == '.' && dir_item->d_name[1] == '.' && dir_item->d_name[2] == '\0')
                )) {
                    char install_match[] = ".pkg.tar.zst";
                    uint32_t name_length;
                    for (name_length = 0; dir_item->d_name[name_length] != '\0'; name_length++);
                    if ((name_length+1) < sizeof(install_match)) {
                        continue;
                    }
                    uint8_t no_match = 0;
                    uint32_t search_offset = name_length+1 - sizeof(install_match);
                    for (uint16_t idx = search_offset; idx < name_length; idx++) {
                        if (dir_item->d_name[idx] != install_match[idx-search_offset]) {
                            no_match = 1;
                            break;
                        }
                    }
                    if (!no_match) {
                        if (dep_install_args_len >= arg_max) {
                            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Too many packages to list (%d max).\n", PATH_MAX);
                            closedir(dir);
                            aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
                            free(built_dep_bases);
                            free(found_pkg_names);
                            cJSON_Delete(required_dependencies);
                            cJSON_Delete(depends_response_body);
                            aur_pkg_info_array_free(pkgs);
                            cJSON_Delete(response_body);
                            for (uint32_t idx = non_dyn_dep_install_args; idx < dep_install_args_len; idx++){
                                free(dep_install_args[idx]);
                            }
                            free(dep_install_args);
                            return 9;
                        }
                        dependency_install_count++;
                        uint32_t d_name_size;
                        for (d_name_size = 0; dir_item->d_name[d_name_size] != '\0'; d_name_size++);
                        uint32_t pkg_str_size;
                        for (pkg_str_size = 0; pkg_base->valuestring[pkg_str_size] != '\0'; pkg_str_size++);
                        char *install_file_path = malloc(d_name_size+pkg_str_size+2);
                        snprintf(install_file_path, d_name_size+pkg_str_size+2, "%s/%s", pkg_base->valuestring, dir_item->d_name);
                        dep_install_args[dep_install_args_len] = install_file_path;
                        dep_install_args_len++;
                    }
                }
            }
            closedir(dir);
            chdir("..");
        }
        dep_install_args[dep_install_args_len] = NULL;
        
        if (dep_install_args_len-non_dyn_dep_install_args) {
            printf("Installing \x1b[1m%d\x1b[0m dependencies...\n", dependency_install_count);
            pid_t pid = fork();
            if (pid < 0) {
                fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Error forking process: %s\n", strerror(errno));
                aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
                for (uint32_t idx = non_dyn_dep_install_args; idx < dep_install_args_len; idx++){
                    free(dep_install_args[idx]);
                }
                free(dep_install_args);
                free(built_dep_bases);
                free(found_pkg_names);
                cJSON_Delete(required_dependencies);
                cJSON_Delete(depends_response_body);
                aur_pkg_info_array_free(pkgs);
                cJSON_Delete(response_body);
                return 64+errno;
            }
            if (pid == 0) {
                execvp("sudo", dep_install_args);
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Pacman failed to run: %s\n", strerror(errno));
                _exit(127);
            }
            for (uint32_t idx = non_dyn_dep_install_args; idx < dep_install_args_len; idx++){
                free(dep_install_args[idx]);
            }
            free(dep_install_args);
            int32_t dep_install_info;
            if (waitpid(pid, &dep_install_info, 0) < 0) {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Waiting for install process failed: %s\n", strerror(errno));
                aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
                free(built_dep_bases);
                free(found_pkg_names);
                cJSON_Delete(required_dependencies);
                cJSON_Delete(depends_response_body);
                aur_pkg_info_array_free(pkgs);
                cJSON_Delete(response_body);
                return 64+errno;
            }
            int dep_install_status = WEXITSTATUS(dep_install_info);
            if (dep_install_status || WIFSIGNALED(dep_install_info)) {
                int return_code = 0;
                if (WIFSIGNALED(dep_install_info)) {
                    if (WTERMSIG(dep_install_info) == SIGINT) {
                        fprintf(stderr, "\x1b[1;33mStopping\x1b[0m: Install process stopped by user\n");
                    } else {
                        fprintf(stderr, "\x1b[1;33mStopping\x1b[0m: Install process exited due to signal %d: %s\n", WTERMSIG(dep_install_info), strsignal(WTERMSIG(dep_install_info)));
                    }
                    return_code = 128 + WTERMSIG(dep_install_info);
                }
                if (dep_install_status) {
                    fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: pacman error %d\n", dep_install_status);
                    return_code = 64;
                }
                aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
                free(built_dep_bases);
                free(found_pkg_names);
                cJSON_Delete(required_dependencies);
                cJSON_Delete(depends_response_body);
                aur_pkg_info_array_free(pkgs);
                cJSON_Delete(response_body);
                return return_code;
            }
        } else {
            for (uint32_t idx = non_dyn_dep_install_args; idx < dep_install_args_len; idx++){
                free(dep_install_args[idx]);
            }
            free(dep_install_args);
        }
        free(built_dep_bases);
        cJSON_Delete(required_dependencies);
        cJSON_Delete(depends_response_body);
    } else {
        free(all_depends);
    }
    int *built_bases = malloc((fetched_bases_count) * sizeof(int));
    int built_bases_count = 0;
    uint32_t install_count = 0;
    uint32_t install_args_len = 0;
    uint32_t arg_max = sysconf(_SC_PAGE_SIZE)*sizeof(int)*CHAR_BIT-1;
    char **install_args = malloc(sizeof(void *)*arg_max);
    for (int32_t pfx =0; install_cmd_prefix[pfx] != NULL; pfx++) {
        install_args[install_args_len] = install_cmd_prefix[pfx];
        install_args_len++;
    }
    uint32_t non_dyn_install_args = install_args_len;
    for (int pkg_idx = 0; pkg_idx < pkgs->size; pkg_idx++) {
        AURPkgInfo *pkg_info = pkgs->items[pkg_idx];
        if (pkg_info->base == NULL || !(pkg_info->base_id)) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Required data for package base or base ID went missing.\n");
            aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
            free(built_bases);
            free(found_pkg_names);
            aur_pkg_info_array_free(pkgs);
            cJSON_Delete(response_body);
            for (uint32_t idx = non_dyn_install_args; idx < install_args_len; idx++){
                free(install_args[idx]);
            }
            free(install_args);
            return 6;
        }
        uint8_t base_match = 0;
        for (int idx = 0; idx < built_bases_count && idx < pkgs->size; idx++) {
            if (pkg_info->base_id == built_bases[idx]) {
                base_match = 1;
            }
        }
        if (base_match) {
            continue;
        }
        built_bases[built_bases_count] = pkg_info->base_id;
        built_bases_count++;
        if (fetched_bases_count > 1) {
            printf("Making Package %d/%d \x1b[1m%s\x1b[0m\n", built_bases_count, fetched_bases_count, pkg_info->base);
        } else {
            printf("Making Package \x1b[1m%s\x1b[0m\n", pkg_info->base);
        }
        chdir(pkg_info->base);
        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Error forking process: %s\n", strerror(errno));
            aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
            free(built_bases);
            free(found_pkg_names);
            aur_pkg_info_array_free(pkgs);
            cJSON_Delete(response_body);
            for (uint32_t idx = non_dyn_install_args; idx < install_args_len; idx++){
                free(install_args[idx]);
            }
            free(install_args);
            return 4;
        }
        if (pid == 0) {
            char *argv[] = {
                "makepkg", "-sf", NULL
            };
            execvp("makepkg", argv);
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Makepkg command failed to run: %s\n", strerror(errno));
            _exit(127);
        }
        int32_t makepkg_status_info;
        if (waitpid(pid, &makepkg_status_info, 0) < 0) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Error waiting for makepkg command: %s\n", strerror(errno));
            aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
            free(built_bases);
            free(found_pkg_names);
            aur_pkg_info_array_free(pkgs);
            cJSON_Delete(response_body);
            for (uint32_t idx = non_dyn_install_args; idx < install_args_len; idx++){
                free(install_args[idx]);
            }
            free(install_args);
            return 4;
        }
        int makepkg_status = WEXITSTATUS(makepkg_status_info);
        if (makepkg_status || WIFSIGNALED(makepkg_status_info)) {
            int return_code = 0;
            if (WIFSIGNALED(makepkg_status_info)) {
                if (WTERMSIG(makepkg_status_info) == SIGINT) {
                    fprintf(stderr, "\x1b[1;33mStopping\x1b[0m: Makepkg process stopped by user\n");
                } else {
                    fprintf(stderr, "\x1b[1;33mStopping\x1b[0m: Makepkg process exited due to signal %d: %s\n", WTERMSIG(makepkg_status_info), strsignal(WTERMSIG(makepkg_status_info)));
                }
                return_code = 128 + WTERMSIG(makepkg_status_info);
            }
            if (makepkg_status) {
                fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: makepkg error %d\n", makepkg_status);
                return_code = 32+ makepkg_status;
            }
            aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
            free(built_bases);
            free(found_pkg_names);
            aur_pkg_info_array_free(pkgs);
            cJSON_Delete(response_body);
            for (uint32_t idx = non_dyn_install_args; idx < install_args_len; idx++){
                free(install_args[idx]);
            }
            free(install_args);
            return return_code;
        }
        DIR *dir = opendir("./");
        if (!dir) { 
            printf("\n");
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: could not list directory\n"); 
            aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
            free(built_bases);
            free(found_pkg_names);
            aur_pkg_info_array_free(pkgs);
            cJSON_Delete(response_body);
            for (uint32_t idx = non_dyn_install_args; idx < install_args_len; idx++){
                free(install_args[idx]);
            }
            free(install_args);
            return 4;
        }
        struct dirent *dir_item;
        while ((dir_item = readdir(dir)) != NULL) {
            if (!(
                (dir_item->d_name[0] == '.' && dir_item->d_name[1] == '\0') 
                || 
                (dir_item->d_name[0] == '.' && dir_item->d_name[1] == '.' && dir_item->d_name[2] == '\0')
            )) {
                char install_match[] = ".pkg.tar.zst";
                uint32_t name_length;
                for (name_length = 0; dir_item->d_name[name_length] != '\0'; name_length++);
                if ((name_length+1) < sizeof(install_match)) {
                    continue;
                }
                uint8_t no_match = 0;
                uint32_t search_offset = name_length+1 - sizeof(install_match);
                for (uint16_t idx = search_offset; idx < name_length; idx++) {
                    if (dir_item->d_name[idx] != install_match[idx-search_offset]) {
                        no_match = 1;
                        break;
                    }
                }
                if (!no_match) {
                    if (install_args_len >= arg_max) {
                        fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Too many packages to list (%d max).\n", arg_max);
                        closedir(dir);
                        aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
                        free(built_bases);
                        free(found_pkg_names);
                        aur_pkg_info_array_free(pkgs);
                        cJSON_Delete(response_body);
                        for (uint32_t idx = non_dyn_install_args; idx < install_args_len; idx++){
                            free(install_args[idx]);
                        }
                        free(install_args);
                        return 9;
                    }
                    install_count++;
                    uint32_t d_name_size;
                    for (d_name_size = 0; dir_item->d_name[d_name_size] != '\0'; d_name_size++);
                    uint32_t pkg_str_size;
                    for (pkg_str_size = 0; pkg_info->base[pkg_str_size] != '\0'; pkg_str_size++);
                    char *install_file_path = malloc(d_name_size+pkg_str_size+2);
                    snprintf(install_file_path, d_name_size+pkg_str_size+2, "%s/%s", pkg_info->base, dir_item->d_name);
                    install_args[install_args_len] = install_file_path;
                    install_args_len++;
                }
            }
        }
        closedir(dir);
        chdir("..");
    }
    aur_pkg_info_array_free(pkgs);
    install_args[install_args_len] = NULL;
    
    if (install_args_len-non_dyn_install_args) {
        printf("Installing \x1b[1m%d\x1b[0m packages...\n", install_count);
        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Error forking process: %s\n", strerror(errno));
            aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
            for (uint32_t idx = non_dyn_install_args; idx < install_args_len; idx++){
                free(install_args[idx]);
            }
            free(install_args);
            free(built_bases);
            free(found_pkg_names);
            cJSON_Delete(response_body);
            return 64+errno;
        }
        if (pid == 0) {
            execvp("sudo", install_args);
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Pacman failed to run: %s\n", strerror(errno));
            _exit(127);
        }
        for (uint32_t idx = non_dyn_install_args; idx < install_args_len; idx++){
            free(install_args[idx]);
        }
        free(install_args);
        int32_t install_info;
        if (waitpid(pid, &install_info, 0) < 0) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Waiting for install process failed: %s\n", strerror(errno));
            aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
            free(built_bases);
            free(found_pkg_names);
            cJSON_Delete(response_body);
            return 64+errno;
        }
        int install_status = WEXITSTATUS(install_info);
        if (install_status || WIFSIGNALED(install_info)) {
            int return_code = 0;
            if (WIFSIGNALED(install_info)) {
                if (WTERMSIG(install_info) == SIGINT) {
                    fprintf(stderr, "\x1b[1;33mStopping\x1b[0m: Install process stopped by user\n");
                } else {
                    fprintf(stderr, "\x1b[1;33mStopping\x1b[0m: Install process exited due to signal %d: %s\n", WTERMSIG(install_info), strsignal(WTERMSIG(install_info)));
                }
                return_code = 128 + WTERMSIG(install_info);
            }
            if (install_status) {
                fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: pacman error %d\n", install_status);
                return_code = 64;
            }
            aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
            free(built_bases);
            free(found_pkg_names);
            cJSON_Delete(response_body);
            return return_code;
        }
    } else {
        for (uint32_t idx = non_dyn_install_args; idx < install_args_len; idx++){
            free(install_args[idx]);
        }
        free(install_args);
    }
    free(built_bases);
    printf("Installation Completed\n");
    aop_full_free((void **)base_dependencies, base_dependencies_amount, free, free);
    free(found_pkg_names);
    cJSON_Delete(response_body);
    return 0;
    
}

int command_c(char *options, char *arguments[], int32_t arg_len, cJSON *_) {
    cJSON_Delete(_);
    (void)(arguments);
    (void)(arg_len);
    uint8_t skip_missing = 0;
    uint8_t skip_upgrade = 0;
    uint8_t upgrade_keyring = 0;
    int32_t ignoring_packages = 0;
    for (uint32_t idx = 0; options[idx] != '\0'; idx++) {
        switch (options[idx]) {
            case 'f':
                skip_missing = 1;
                break;
            case 'k':
                upgrade_keyring = 1;
                break;
            case 's':
                skip_upgrade = 1;
                break;
            case 'i':
                ignoring_packages = 1;
        }
    }
    // todo: add proper options for this command.
    printf("Checking for newer versions of AUR packages...\n");
    alpm_errno_t err;
    alpm_handle_t * handle = alpm_initialize("/", PACMAN_DB_PATH, &err);
    if (handle == NULL) {
        fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: ALPM Error %d: %s\n", err, alpm_strerror(err));
        return 4;
    }
    alpm_db_t * local_db = alpm_get_localdb(handle);
    alpm_list_t * packages = alpm_db_get_pkgcache(local_db);
    char sync_dirname[] = "sync";
    char *sync_dir_path = malloc(sizeof(PACMAN_DB_PATH)+sizeof(sync_dirname));
    snprintf(sync_dir_path, sizeof(PACMAN_DB_PATH)+sizeof(sync_dirname), "%s/%s", PACMAN_DB_PATH, sync_dirname);
    DIR *sync_dir = opendir(sync_dir_path);
    free(sync_dir_path);
    if (sync_dir == NULL) {
        fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: could not list db sync directory\n"); 
        alpm_release(handle);
        return 4;
    }
    struct dirent *dir_item;
    while ((dir_item = readdir(sync_dir)) != NULL) {
        if (
            (dir_item->d_name[0] == '.' && dir_item->d_name[1] == '\0') 
            || 
            (dir_item->d_name[0] == '.' && dir_item->d_name[1] == '.' && dir_item->d_name[2] == '\0')
        ) {
            continue;
        }
        uint32_t name_size;
        for (name_size = 0; dir_item->d_name[name_size] != '\0'; name_size++);
        if (name_size < 3) {
            continue;
        }
        dir_item->d_name[name_size - 3] = '\0';
        alpm_register_syncdb(handle, dir_item->d_name, 0);
    }
    closedir(sync_dir);
    alpm_list_t *sync_dbs = alpm_get_syncdbs(handle);
    if (sync_dbs == NULL) {
        fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Can't check for AUR packages due to missing or empty pacman database\n");
        alpm_release(handle);
        return 6;
    }
    uint32_t install_count = 0;
    char debug_match[] = "-debug";
    uint8_t skip = 0;
    for(alpm_list_t *i = packages; i; i = alpm_list_next(i)) {
		alpm_pkg_t *pkg = i->data;
        const char *pkgname = alpm_pkg_get_name(pkg);
        for(alpm_list_t *j = sync_dbs; j; j = alpm_list_next(j)) {
            if(alpm_db_get_pkg(j->data, pkgname)) {
                skip = 1;
            }
        }
        uint8_t matches = 0;
        uint32_t pkgname_len;
        for(pkgname_len = 0; pkgname[pkgname_len] != '\0'; pkgname_len++);
        if (pkgname_len >= 6) {
            for (uint8_t idx = 0; idx < 6; idx++) {
                if (debug_match[idx] == pkgname[pkgname_len-(6-idx)]) {
                    matches++;
                }
            }
        }
        if (matches == 6) {
            skip = 1;
        }
        for (uint32_t idx = 0; pkgname[idx] == debug_match[idx]; idx++) {
            if (pkgname[idx] == '\0') {
                skip = 1;
                break;
            }
        }
        if (skip){
            skip = 0;
            continue;
        }
        install_count++;
    }
    printf("Checking %u AUR packages...\n", install_count);
    InstalledPkgInfo **installed_pkgs = malloc(install_count * sizeof(void *));
    uint32_t install_idx = 0;
    skip = 0;
    for(alpm_list_t *i = packages; i; i = alpm_list_next(i)) {
		alpm_pkg_t *pkg = i->data;
        const char *pkgname = alpm_pkg_get_name(pkg);
        const char *pkgver = alpm_pkg_get_version(pkg);
        uint32_t pkgname_len;
        for(pkgname_len = 0; pkgname[pkgname_len] != '\0'; pkgname_len++);
        uint32_t pkgver_len;
        for(pkgver_len = 0; pkgver[pkgver_len] != '\0'; pkgver_len++);

        for(alpm_list_t *j = sync_dbs; j; j = alpm_list_next(j)) {
            if(alpm_db_get_pkg(j->data, pkgname)) {
                skip = 1;
            }
        }
        uint8_t matches = 0;
        if (pkgname_len >= 6) {
            for (uint8_t idx = 0; idx < 6; idx++) {
                if (debug_match[idx] == pkgname[pkgname_len-(6-idx)]) {
                    matches++;
                }
            }
        }
        if (matches == 6) {
            skip = 1;
        }
        for (uint32_t idx = 0; pkgname[idx] == debug_match[idx]; idx++) {
            if (pkgname[idx] == '\0') {
                skip = 1;
                break;
            }
        }
        if (skip){
            skip = 0;
            continue;
        }
        
        char *to_copy_name = malloc(pkgname_len+1);
        installed_pkgs[install_idx] = malloc(sizeof(InstalledPkgInfo));
        snprintf(to_copy_name, pkgname_len+1, "%s", pkgname);
        installed_pkgs[install_idx]->name = to_copy_name;
        char *to_copy_version = malloc(pkgver_len+1);
        snprintf(to_copy_version, pkgver_len+1, "%s", pkgver);
        installed_pkgs[install_idx]->version = to_copy_version;
        install_idx++;
    }
    alpm_release(handle);
    uint8_t status;
    /*
    find_pkg Status Codes:
    0: OK
    2: Package not found
    3: cURL init failed
    4: cURL perform error 
    5: HTTP error
    6: AURWebRTC error
    7: HTTP response content type was not 'application/json'
    8: cJSON parsing error
    9: JSON key error
    */
    char **installed_names = malloc(install_count * sizeof(void *));
    for (uint32_t i = 0; i < install_idx; i++) {
        installed_names[i] = installed_pkgs[i]->name;
    }
    cJSON *response_body = find_pkg(installed_names, install_count, skip_missing, &status);
    free(installed_names);
    if (status) {
        cJSON_Delete(response_body);
        installed_pkg_info_array_free(installed_pkgs, install_count);
        return status;
    }
    if (cJSON_IsNull(response_body)) {
        fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API metadata went missing.\n");
        installed_pkg_info_array_free(installed_pkgs, install_count);
        return 6;
    }
    cJSON *found_packages = cJSON_GetObjectItemCaseSensitive(response_body, "results");
    if (!found_packages) {
        cJSON_Delete(response_body);
        fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API results went missing.\n");
        installed_pkg_info_array_free(installed_pkgs, install_count);
        return 6;
    }
    if (!cJSON_GetArraySize(found_packages)) {
        cJSON_Delete(response_body);
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: No packages to install, exiting...\n");
        installed_pkg_info_array_free(installed_pkgs, install_count);
        return 8;
    }
    AURPkgInfoArray *pkgs = new_aur_pkg_info_array(found_packages);
    // Note: this will share addresses from installed_pkgs so no need to free() each element or will result in double free.
    char **needs_update = malloc(pkgs->size * sizeof(void *));
    cJSON *package_data = cJSON_CreateArray();
    uint32_t outdated_count = 0;
    uint32_t pkg_num = 0;
    if (pkgs == NULL) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: Memory allocation error: %s\n", strerror(errno));
        cJSON_Delete(response_body);
        installed_pkg_info_array_free(installed_pkgs, install_count);
        return 8;
    }
    for (int pkg_idx = 0; pkg_idx < pkgs->size; pkg_idx++) {
        if (pkgs->items[pkg_idx]->name && pkgs->items[pkg_idx]->version) {
            uint32_t outdated = 1;
            uint32_t missing = 1;
            for (uint32_t idx = 0; installed_pkgs[pkg_num]->name[idx] == pkgs->items[pkg_idx]->name[idx]; idx++) {
                if (pkgs->items[pkg_idx]->name[idx] == '\0') {
                    missing = 0;
                    break;
                }
            }
            if (missing) {
                pkg_num++;
            }
            for (uint32_t idx = 0; installed_pkgs[pkg_num]->version[idx] == pkgs->items[pkg_idx]->version[idx]; idx++) {
                if (pkgs->items[pkg_idx]->version[idx] == '\0') {
                    outdated = 0;
                    break;
                }
            }
            if (outdated) {
                int32_t ignore_match = 0;
                if (ignoring_packages) {
                    for (int32_t idx = 0; idx < arg_len; idx++) {
                        for (uint32_t str_idx = 0; installed_pkgs[pkg_num]->name[str_idx] == arguments[idx][str_idx]; str_idx++) {
                            if (installed_pkgs[pkg_num]->name[str_idx] == '\0') {
                                ignore_match = 1;
                                break;
                            }
                        }
                    }
                }
                if (ignore_match) {
                    printf("Skipping %s\n", installed_pkgs[pkg_num]->name);
                } else {
                    // Note: shares addresses from installed_pkgs
                    needs_update[outdated_count] = installed_pkgs[pkg_num]->name;
                    cJSON_AddItemReferenceToArray(package_data, (cJSON *) cJSON_GetArrayItem(found_packages, pkg_idx));
                    outdated_count++;
                }
            }
        }
        pkg_num++;
    }
    aur_pkg_info_array_free(pkgs);
    if (!outdated_count) {
        printf("\x1b[1mAll installed AUR packages are up to date\x1b[0m\n");
        // free everything
        cJSON_Delete(response_body);
        installed_pkg_info_array_free(installed_pkgs, install_count);
        cJSON_Delete(package_data);
        free(needs_update);
        return 0;
    }
    printf("%u AUR packages can be upgraded:\n    ", outdated_count);
    for (uint32_t stringsi = 0; stringsi < outdated_count; stringsi++) {
        if (stringsi) {
            printf(" ");
        }
        printf("%s", needs_update[stringsi]);
    }
    printf("\n");
    printf("Upgrade these packages now? [Y/n]: ");
    char prompt[6];
    char *input_successful = fgets(prompt, sizeof(prompt), stdin);
    if (input_successful && prompt[0] != '\n' && (prompt[0] | 32) == 'n') {
        // free everything
        cJSON_Delete(response_body);
        installed_pkg_info_array_free(installed_pkgs, install_count);
        cJSON_Delete(package_data);
        free(needs_update);
        return 0;
    }
    printf("It is recommended to run pacman -Syu before upgrading these packages\n");
    if (!skip_upgrade) {
        printf("Note: pass the s argument to skip running running pacman -Syu\n");
        printf(
            "Note: If you run into package signature errors, " 
            "try upgrading the archlinux-keyring by passing the k argument\n"
        );
        if (upgrade_keyring) {
            printf("Attempting to upgrade archlinux-keyring first to prevent signature errors...\n");
            pid_t pid = fork();
            if (pid < 0) {
                fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Error forking process: %s\n", strerror(errno));
                cJSON_Delete(response_body);
                installed_pkg_info_array_free(installed_pkgs, install_count);
                cJSON_Delete(package_data);
                free(needs_update);
                return 64+errno;
            }
            if (pid == 0) {
                char *argv[] = {
                    "sudo", "pacman", "-Sy", "archlinux-keyring", NULL
                };
                execvp("sudo", argv);
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Pacman failed to run: %s\n", strerror(errno));
                _exit(127);
            }
            int32_t keyring_status;
            if (waitpid(pid, &keyring_status, 0) < 0) {
                fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Error waiting for pacman: %s\n", strerror(errno));
                cJSON_Delete(response_body);
                installed_pkg_info_array_free(installed_pkgs, install_count);
                cJSON_Delete(package_data);
                free(needs_update);
                return 64+errno;
            }
            int keyring_failed = WEXITSTATUS(keyring_status);
            if (WIFSIGNALED(keyring_status)) {
                if (WTERMSIG(keyring_status) == SIGINT) {
                    fprintf(stderr, "\x1b[1;33mStopping\x1b[0m: Pacman stopped by user\n");
                } else {
                    fprintf(
                        stderr, "\x1b[1;33mStopping\x1b[0m: Pacman exited due to signal %d: %s\n", 
                        WTERMSIG(keyring_status), strsignal(WTERMSIG(keyring_status)));
                }
                cJSON_Delete(response_body);
                installed_pkg_info_array_free(installed_pkgs, install_count);
                cJSON_Delete(package_data);
                free(needs_update);
                return 128+WTERMSIG(keyring_status);
            }
            if (keyring_failed) {
                fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Pacman failed with exit code %d\n", keyring_failed);
                cJSON_Delete(response_body);
                installed_pkg_info_array_free(installed_pkgs, install_count);
                cJSON_Delete(package_data);
                free(needs_update);
                return 64;
            }
            printf("Successfully upgraded archlinux-keyring\n");
            printf(
                "\x1b[1;33mWARNING\x1b[0m: The system has been \x1b[mPARTIALLY UPGRADED!\x1b[0m "
                "In other words aborting now and not fully upgrading with pacman -Syu may leave your "
                "system in a broken state! So please let it run or do it manually\n"
            );
        }
        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Error forking process: %s\n", strerror(errno));
            cJSON_Delete(package_data);
            cJSON_Delete(response_body);
            installed_pkg_info_array_free(installed_pkgs, install_count);
            free(needs_update);
            return 64+errno;
        }
        if (pid == 0) {
            char *argv[] = {
                "sudo", "pacman", "-Syu", NULL
            };
            execvp("sudo", argv);
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: pacman failed to run: %s\n", strerror(errno));
            _exit(127);
        }
        int32_t pacman_status;
        if (waitpid(pid, &pacman_status, 0) < 0) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Error waiting for pacman: %s\n", strerror(errno));
            cJSON_Delete(package_data);
            cJSON_Delete(response_body);
            installed_pkg_info_array_free(installed_pkgs, install_count);
            free(needs_update);
            return 64+errno;
        }
        int pacman_failed = WEXITSTATUS(pacman_status);
        if (WIFSIGNALED(pacman_status)) {
            if (WTERMSIG(pacman_status) == SIGINT) {
                fprintf(stderr, "\x1b[1;33mStopping\x1b[0m: Pacman stopped by user\n");
            } else {
                fprintf(
                    stderr, "\x1b[1;33mStopping\x1b[0m: Pacman exited due to signal %d: %s\n", 
                    WTERMSIG(pacman_status), strsignal(WTERMSIG(pacman_status)));
            }cJSON_Delete(response_body);
            installed_pkg_info_array_free(installed_pkgs, install_count);
            cJSON_Delete(package_data);
            free(needs_update);
            return 128+WTERMSIG(pacman_status);
        }
        if (pacman_failed) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Pacman failed with exit code %d\n", pacman_failed);
            cJSON_Delete(package_data);
            cJSON_Delete(response_body);
            installed_pkg_info_array_free(installed_pkgs, install_count);
            free(needs_update);
            return 64;
        }
    }
    char **arg_list = NULL;
    int32_t arg_list_len;
    if (ignoring_packages) {
        arg_list_len = 0;
        arg_list = malloc(sizeof(void *)*(outdated_count+arg_len));
        for (uint32_t idx = 0; idx < outdated_count; idx++) {
            int32_t item_length;
            for (item_length = 0; needs_update[idx][item_length] != '\0'; item_length++);
            char *item = malloc(item_length+1);
            snprintf(item, item_length+1, "%s", needs_update[idx]);
            arg_list[arg_list_len] = item;
            arg_list_len++;
        }
        for (int32_t idx = 0; idx < arg_len; idx++) {
            int32_t item_length;
            for (item_length = 0; arguments[idx][item_length] != '\0'; item_length++);
            char *item = malloc(item_length+2);
            snprintf(item, item_length+2, "-%s", arguments[idx]);
            arg_list[arg_list_len] = item;
            arg_list_len++;
        }
    } else {
        arg_list_len = outdated_count;
        arg_list = needs_update;
    }
    uint8_t return_code = command_i(options, arg_list, arg_list_len, package_data);
    if (ignoring_packages) {
        aop_full_free((void **)arg_list, arg_list_len, free, free);
    }
    cJSON_Delete(package_data);
    cJSON_Delete(response_body);
    installed_pkg_info_array_free(installed_pkgs, install_count);
    free(needs_update);
    // printf("%u\n", install_count);
    return return_code;
}

int main(int32_t argc, char *argv[]) {
    printf("%s %s\n%s %s\n", LONG_NAME, VERSION, COPYRIGHT, AUTHOR);

    uid_t uid = getuid();
    if (uid == 0) {
        fprintf(stderr, "Support for running this program as root is not yet implemented!\n");
        return 1;
    }

    if (argc < 2) {
        fprintf(stderr,
            "No commands provided!\nUsage: %s [command][options] [arguments]\nSee %s -H for details\n", 
            SHORT_NAME, SHORT_NAME
        );
        return 1;
    }

    char *command_arg = argv[1];

    if (command_arg[0] != '-') {
        uint8_t n_matches;
        char *match = "help";
        for (n_matches = 0; n_matches < 4; n_matches++) {
            if (command_arg[n_matches] != match[n_matches]) {
                break;
            }
        }
        if (n_matches == 4) {
            command_arg = "-H";
        }
    }
    char **command_args = malloc((argc-2)*sizeof(void *));
    if (argc > 2) {
        for (int32_t i = 2; i < argc; i++) {
            command_args[i-2] = argv[i];
        }
    }
    uint8_t return_code = 0;
    if (command_arg[0] == '-' && command_arg[1] != '\0') {
        char cmd_name;
        if (command_arg[1] != '-') {
            cmd_name = command_arg[1];
        } else {
            cmd_name = command_arg[2];
        }
        int8_t arg_size;
        for (arg_size = -2; command_arg[arg_size+2] != '\0'; arg_size++);
        char cmd_opts[arg_size+1];
        uint32_t idx;
        for (idx = 2;; idx++) {
            cmd_opts[idx-2] = command_arg[idx];
            if (command_arg[idx] == '\0') {
                break;
            }
        }
        for (uint64_t cmd_idx = 0; cmd_idx < ARRAY_SIZE(commands); cmd_idx++) {
            if ((cmd_name & 95) == commands[cmd_idx].name) {
                return_code = commands[cmd_idx].callback(cmd_opts, command_args, argc-2, cJSON_CreateNull());
                free(command_args);
                break;
            } else if (cmd_idx == 6) {
                fprintf(stderr, "%s: command \"%c\" not found\n", SHORT_NAME, cmd_name);
                return_code = 2;
            }
            
        }
    }
    return return_code;
}
