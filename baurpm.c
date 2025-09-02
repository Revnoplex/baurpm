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

#define LONG_NAME "Basic Arch User Repository (AUR) Package Manager"
#define SHORT_NAME "baurpm"
#define VERSION "0.1.0a"
#define AUTHOR "Revnoplex"
#define LICENSE "MIT"
#define COPYRIGHT "Copyright (c) 2022-2025"
#define AUR_BASE_URL "https://aur.archlinux.org"

typedef int (*stdcall)(char *, char *[], int32_t, cJSON *);

struct memory {
    /*
    Source: https://github.com/curl/curl/blob/master/docs/libcurl/opts/CURLOPT_WRITEFUNCTION.md
    Copyright: https://github.com/curl/curl/blob/master/COPYING
    SPDX-License-Identifier: curl
    */
    char *response;
    size_t size;
  };
   

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

static int extract(const char *filename) {
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

    // construct the string with 4 significant figures
    snprintf(
        rep_buffer, buffer_size, "%.4g %s", 
        (double) byte_size/u64_pow(1024, xp), 
        (byte_size == 1) ? "byte" : unit_names[xp]
    );
    return rep_buffer;
}

cJSON *find_pkg(char *package_names[], int32_t pkg_len, uint8_t ignore_missing, uint8_t *status) {
    const char *err_msg_prefix = "\x1b[1;31mFatal\x1b[0m: Failed to get information on the package/s: "; 
    if (!pkg_len) {
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: No packages were given to look for.\n");
        *status = 20;
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
            *status = 4;
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
            *status = 4;
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
                *status = 7;
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
            *status = 8;
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
            *status = 9;
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
                    *status = 6;
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
                *status = 6;
                return parsed_response;
            }
        }
        cJSON *result_count_key = cJSON_GetObjectItemCaseSensitive(parsed_response, "resultcount");
        int32_t result_count;
        if (result_count_key && cJSON_IsNumber(result_count_key)) {
            result_count = result_count_key->valueint;
        } else {
            *status = 9;
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
    *status = 3;
    return cJSON_CreateNull();

}

char *download_pkg(char *url_path, uint8_t *status) {
    const char *err_msg_prefix = "\x1b[1;31mFatal\x1b[0m: Failed to download the package: "; 
    uid_t uid = getuid();
    struct passwd* pwd = getpwuid(uid);

    if (!pwd) {
        fprintf(stderr, "%sPasswd Error", err_msg_prefix);
        *status = 10;
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
        *status = 11;
        return "";
    }
    uint32_t path_size = dirc + sizeof_url_path-slash_index;
    char *download_path = malloc(path_size);
    snprintf(download_path, path_size, "%s/%s", downloads_dir_buffer, file_name_buffer);
    
    free(downloads_dir_buffer);
    
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

        uint32_t download_size = ftell(download_ptr);
        /* once the request has been performed, 
        it would have finished writing to the file as it is a blocking call.
        So we can close it now */
        fclose(download_ptr);
        // And we won't need the url anymore.
        free(url_buffer);

        /* Check for errors */
        if (res) {
            fprintf(stderr, "\r%scURL Error %d: %s\n", err_msg_prefix, res, curl_easy_strerror(res));
            *status = 4;
            free(file_name_buffer);
            curl_easy_cleanup(curl);
            free(aur_netloc);
            return download_path;
        }

        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

        // That is the last usage of curl so we can free it from memory.
        curl_easy_cleanup(curl);

        // Check for HTTP errors
        if (response_code >= 400) {
            fprintf(stderr, "\r%sHTTP Error %ld\n", err_msg_prefix, response_code);
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
    *status = 3;
    return download_path;

}

uint32_t download_and_extract_pkgs(cJSON *pkgv, uint32_t pkgc) {
    char **downloaded_bases = malloc(pkgc * sizeof(void *));
    uint32_t downloaded_bases_count = 0;
    const cJSON *package = NULL;
    cJSON_ArrayForEach(package, pkgv) {
        cJSON *pkg_name = cJSON_GetObjectItemCaseSensitive(package, "Name");
        cJSON *pkg_base = cJSON_GetObjectItemCaseSensitive(package, "PackageBase");
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
        uint8_t different_base = 0;
        for (uint32_t idx = 0; pkg_name->valuestring[idx] != '\0'; idx++) {
            if (pkg_name->valuestring[idx] != pkg_base->valuestring[idx]) {
                different_base = 1;
                break;
            }
        }
        cJSON *url_path = cJSON_GetObjectItemCaseSensitive(package, "URLPath");
        char *url_path_string = url_path->valuestring;
        char *base_url = NULL;
        if (different_base) {
            uint32_t slash_index = 0;
            uint32_t suffix_length = 0;
            uint32_t suffix_index = 0;
            uint8_t traversed = 0;
            for (uint32_t idx = 0;;idx++) {
                if (url_path_string[idx] == '/') {
                    slash_index = idx;
                }
                if (suffix_length) {
                    suffix_length++;
                }
                if (url_path_string[idx] == '.' && traversed && !suffix_length) {
                    suffix_index = idx;
                    suffix_length++;
                }
                if (url_path_string[idx] == '\0' && !traversed) {
                    idx = slash_index;
                    traversed = 1;
                }
                if (url_path_string[idx] == '\0' && traversed) {
                    break;
                }
            }
            uint32_t base_length;
            for (base_length = 0; pkg_base->valuestring[base_length] != '\0'; base_length++);
            uint32_t base_url_length = slash_index+1 + base_length + suffix_length;
            base_url = malloc(base_url_length);
            // constructs url if the package has a different base.
            for (uint32_t idx = 0; idx < base_url_length; idx++) {
                if (idx <= slash_index) {
                    base_url[idx] = url_path_string[idx];
                    continue;
                }
                if (idx <= slash_index+base_length) {
                    base_url[idx] = pkg_base->valuestring[idx-slash_index-1];
                    continue;
                }
                base_url[idx] = url_path_string[suffix_index+idx-base_length-slash_index-1];
            }
        }
        if (!((url_path && cJSON_IsString(url_path)) || base_url)) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to extract url from package info\n");
            break;
        }
        uint8_t download_status;
        char *provider_url = url_path->valuestring;
        if (base_url) {
            provider_url = base_url;
        }
        // download
        char *download_path = download_pkg(provider_url, &download_status);
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
            return 12;
        }
        uid_t uid = getuid();
        struct passwd* pwd = getpwuid(uid);

        if (!pwd) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Could not get home directory\n");
            free(download_path);
            free(downloaded_bases);
            return 10;
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
        int extraction_failed = extract(download_path);
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

struct commandDocs {
    char names[7];
    char *descriptions[7];
    char *usages[7];
    char *options[7][8];
};

int command_h(char *options, char *arguments[], int32_t arg_len, cJSON * _) {
    cJSON_Delete(_);
    (void)(options);
    struct commandDocs command_docs = {
        { 'H', 'G', 'I', 'C', 'U', 'V', 'A' },
        { 
            "Displays this message", 
            "Get info on an AUR package", 
            "Install an AUR package without keeping the download", 
            "Check for newer versions of installed packages", 
            "Upgrade packages that have been downloaded in ~/stored-aur-packages (not yet implemented)", 
            "", 
            "Install an AUR packages while keeping the download" 
        },
        {
            " [command-name]",
            " [package]",
            "[options] [package(s)]",
            "[options] [arguments]",
            "",
            "",
            ""
        },
        {
            { "" },
            { "" },
            { "f: Ignore any missing packages", "n: Skip reading PKGBUILD files", "" }, 
            { 
                "i, <packages>: Ignore upgrading packages specified", 
                "f: Ignore any missing packages", 
                "n: Skip reading PKGBUILD files",
                "s: Skip running pacman -Syu",
                "k: Upgrade archlinux-keyring first",
                ""
            },
            { "" },
            { "" },
            { "" },
        },
    };

    if (arg_len) {
        int32_t cmd_idx;
        for (cmd_idx = 0; cmd_idx < 7; cmd_idx++) {
            if ((arguments[0][0] & 95) == command_docs.names[cmd_idx]) {
                char *description;
                if (command_docs.descriptions[cmd_idx][0]) {
                    description = command_docs.descriptions[cmd_idx];
                } else {
                    description = "**No Description**";
                }
                printf("%c: %s\n", command_docs.names[cmd_idx], description);
                if (command_docs.usages[cmd_idx][0]) {
                    printf(
                        "Usage:\n    baurpm -%c%s\n", command_docs.names[cmd_idx], command_docs.usages[cmd_idx]
                    );
                } else {
                    printf("**No Usage**\n");
                }
                if (command_docs.options[cmd_idx][0][0]) {
                    printf("Options:\n");
                    int32_t opt_idx;
                    for (opt_idx = 0; command_docs.options[cmd_idx][opt_idx][0] != '\0'; opt_idx++) {
                        printf("    %s\n", command_docs.options[cmd_idx][opt_idx]);
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
        int32_t cmd_idx;
        for (cmd_idx = 0; cmd_idx < 7; cmd_idx++) {
            char *description;
            if (command_docs.descriptions[cmd_idx][0]) {
                description = command_docs.descriptions[cmd_idx];
            } else {
                description = "**No Description**";
            }
            printf("-%c\t%s\n", command_docs.names[cmd_idx], description);
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
    response_body = find_pkg(arguments, arg_len, 0, &status);
    if (status) {
        cJSON_Delete(response_body);
        return status;
    }
    if (cJSON_IsNull(response_body)) {
        fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API metadata went missing.\n");
        return 9;
    }
    cJSON *found_packages = cJSON_GetObjectItemCaseSensitive(response_body, "results");
    if (!found_packages) {
        fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API results went missing.\n");
        cJSON_Delete(response_body);
        return 9;
    }
    
    const cJSON *package = NULL;
    uint32_t found_pkg_arrc = cJSON_GetArraySize(found_packages);
    found_pkg_names = malloc(found_pkg_arrc * sizeof(void *));
    uint32_t pkgsc = 0;
    cJSON_ArrayForEach(package, found_packages) {
        cJSON *name = cJSON_GetObjectItemCaseSensitive(package, "Name");
        if (name && name->valuestring) {
            found_pkg_names[pkgsc] = name->valuestring;
            pkgsc++;
        }
    }
    if (pkgsc == 1) {
        printf("A package called \033[1m%s\033[0m was found.\n", found_pkg_names[0]);
    } else {
        printf("Some packages called \033[1m");
        print_string_array(found_pkg_names, pkgsc);
        printf("\033[0m were found.\n");
    }
    cJSON_ArrayForEach(package, found_packages) {
        cJSON *pkg_name = cJSON_GetObjectItemCaseSensitive(package, "Name");
        printf("View information for %s? [y/n]: ", pkg_name->valuestring);
        char prompt[6];
        char *input_successful = fgets(prompt, sizeof(prompt), stdin);
        if (!(input_successful && prompt[0] != '\n' && (prompt[0] | 32) == 'y')) {
            continue;
        }
        cJSON *pkg_base = cJSON_GetObjectItemCaseSensitive(package, "PackageBase");
        uint8_t different_base = 0;
        for (uint32_t idx = 0; pkg_name->valuestring[idx] != '\0'; idx++) {
            if (pkg_name->valuestring[idx] != pkg_base->valuestring[idx]) {
                different_base = 1;
                break;
            }
        }
        if (different_base) {
            printf(
                "Note: %s has a different package base called %s.\n", 
                pkg_name->valuestring, pkg_base->valuestring
            );
        }
        uint32_t space_size = 0;
        cJSON *item = NULL;
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
        printf("Download and view build files and PKGBUILD? [y/n]: ");
        input_successful = fgets(prompt, sizeof(prompt), stdin);
        if (!(input_successful && prompt[0] != '\n' && (prompt[0] | 32) == 'y')) {
            continue;
        }
        cJSON *url_path = cJSON_GetObjectItemCaseSensitive(package, "URLPath");
        char *url_path_string = url_path->valuestring;
        char *base_url = NULL;
        if (different_base) {
            uint32_t slash_index = 0;
            uint32_t suffix_length = 0;
            uint32_t suffix_index = 0;
            uint8_t traversed = 0;
            for (uint32_t idx = 0;;idx++) {
                if (url_path_string[idx] == '/') {
                    slash_index = idx;
                }
                if (suffix_length) {
                    suffix_length++;
                }
                if (url_path_string[idx] == '.' && traversed && !suffix_length) {
                    suffix_index = idx;
                    suffix_length++;
                }
                if (url_path_string[idx] == '\0' && !traversed) {
                    idx = slash_index;
                    traversed = 1;
                }
                if (url_path_string[idx] == '\0' && traversed) {
                    break;
                }
            }
            uint32_t base_length;
            for (base_length = 0; pkg_base->valuestring[base_length] != '\0'; base_length++);
            uint32_t base_url_length = slash_index+1 + base_length + suffix_length;
            base_url = malloc(base_url_length);
            for (uint32_t idx = 0; idx < base_url_length; idx++) {
                if (idx <= slash_index) {
                    base_url[idx] = url_path_string[idx];
                    continue;
                }
                if (idx <= slash_index+base_length) {
                    base_url[idx] = pkg_base->valuestring[idx-slash_index-1];
                    continue;
                }
                base_url[idx] = url_path_string[suffix_index+idx-base_length-slash_index-1];
            }
        }
        if (!((url_path && cJSON_IsString(url_path)) || base_url)) {
            fprintf(stderr, "\x1b[1;31mError\x1b[0m: Failed to extract url from package info\n");
            break;
        }
        uint8_t download_status;
        char *provider_url = url_path->valuestring;
        if (base_url) {
            provider_url = base_url;
        }
        char *download_path = download_pkg(provider_url, &download_status);
        if (base_url) {
            free(base_url);
        }
        if (download_status) {
            if (*download_path) {
                free(download_path);
            }
            free(found_pkg_names);
            cJSON_Delete(response_body);
            return download_status;
        }
        if (!*download_path) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API metadata went missing.\n");
            free(found_pkg_names);
            cJSON_Delete(response_body);
            return 12;
        }
        uid_t uid = getuid();
        struct passwd* pwd = getpwuid(uid);

        if (!pwd) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Could not get home directory");
            return 10;
        }
        uint32_t hdirc;
        for (hdirc = 0; pwd->pw_dir[hdirc] != '\0'; hdirc++);
        char cache_dir[] = ".cache/baurpm";
        uint32_t dirc = hdirc + sizeof(cache_dir) + 1;
        char *cache_dir_buffer = malloc(dirc);
        snprintf(cache_dir_buffer, dirc, "%s/%s", pwd->pw_dir, cache_dir);
        chdir(cache_dir_buffer);
        free(cache_dir_buffer);
        int extraction_failed = extract(download_path);
        if (extraction_failed) {
            free(download_path);
            free(found_pkg_names);
            cJSON_Delete(response_body);
            return extraction_failed;
        }
        free(download_path);
        printf("Build files for \033[1m%s\033[0m are:\n     ", pkg_base->valuestring);
        DIR *dir = opendir(pkg_base->valuestring);
        if (!dir) { 
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: could not list directory\n"); 
            return 13;
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
        printf("See \033[1m~/.cache/baurpm/%s\033[0m for more information.\n", pkg_base->valuestring);
        printf("Press Enter to continue and view PKGBUILD");
        getchar();
        chdir(pkg_base->valuestring);
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
    }
    free(found_pkg_names);
    cJSON_Delete(response_body);
    return 0;
}

int command_i(char *options, char *arguments[], int32_t arg_len, cJSON *package_data) {
    uint8_t skip_missing = 0;
    uint8_t skip_review = 0;
    for (uint32_t idx = 0; options[idx] != '\0'; idx++) {
        switch (options[idx]) {
            case 'f':
                skip_missing = 1;
                break;
            case 'n':
                skip_review = 1;
        }
    }
    if (!arg_len) {
        fprintf(stderr, "No package names specified!\nFor usage, see %s -H for details\n", SHORT_NAME);
        if (cJSON_IsNull(package_data)) {
            cJSON_Delete(package_data);
        }
        return 1;
    }
    cJSON *response_body = NULL;
    cJSON *found_packages = NULL;
    uint8_t status;
    if (!cJSON_IsNull(package_data)) {
        printf("Using pre-fetched package data...\n");
        found_packages = package_data;
    } else {
        cJSON_Delete(package_data);
    
        printf("Searching for \x1b[1m");
        print_string_array(arguments, arg_len);
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
        response_body = find_pkg(arguments, arg_len, skip_missing, &status);
        if (status) {
            cJSON_Delete(response_body);
            return status;
        }
        if (cJSON_IsNull(response_body)) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API metadata went missing.\n");
            return 9;
        }
        found_packages = cJSON_GetObjectItemCaseSensitive(response_body, "results");
    }
    if (!found_packages) {
        fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API results went missing.\n");
        cJSON_Delete(response_body);
        return 9;
    }
    if (!cJSON_GetArraySize(found_packages)) {
        cJSON_Delete(response_body);
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: No packages to install, exiting...\n");
        return 2;
    }
    cJSON *package = NULL;
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
    char *input_successful = NULL;
    char prompt[6];
    if (cJSON_IsNull(package_data)) {
        if (pkgsc == 1) {
            printf("A package called \033[1m%s\033[0m was found.\nMake and install the package? [Y/n]: ", found_pkg_names[0]);
        } else {
            printf("Some packages called \033[1m");
            print_string_array(found_pkg_names, pkgsc);
            printf("\033[0m were found.\nMake and install the packages? [Y/n]: ");
        }
        input_successful = fgets(prompt, sizeof(prompt), stdin);
        if (!(input_successful && prompt[0] != '\n' && (prompt[0] | 32) == 'y')) {
            printf("Installation aborted\n");
            free(found_pkg_names);
            cJSON_Delete(response_body);
            return 0;
        }
    }
    printf("Downloading packages...\n");
    uint32_t download_and_extraction_failed = download_and_extract_pkgs(found_packages, found_pkg_arrc);
    if (download_and_extraction_failed) {
        free(found_pkg_names);
        cJSON_Delete(response_body);
        return download_and_extraction_failed;
    }
    char **fetched_bases = malloc(found_pkg_arrc * sizeof(void *));
    uint32_t fetched_bases_count = 0;
    cJSON_ArrayForEach(package, found_packages) {
        cJSON *pkg_name = cJSON_GetObjectItemCaseSensitive(package, "Name");
        cJSON *pkg_base = cJSON_GetObjectItemCaseSensitive(package, "PackageBase");
        uint8_t different_base = 0;
        for (uint32_t idx = 0; pkg_name->valuestring[idx] != '\0'; idx++) {
            if (pkg_name->valuestring[idx] != pkg_base->valuestring[idx]) {
                different_base = 1;
                break;
            }
        }
        if (different_base) {
            printf(
                "Note: %s has a different package base called %s.\n", 
                pkg_name->valuestring, pkg_base->valuestring
            );
        }
        uint8_t base_match = 0;
        for (uint32_t idx = 0; idx < fetched_bases_count && idx < found_pkg_arrc; idx++) {
            for (uint32_t str_idx = 0; pkg_base->valuestring[str_idx] == fetched_bases[idx][str_idx]; str_idx++) {
                if (pkg_base->valuestring[str_idx] == '\0') {
                    base_match = 1;
                    break;
                }
            }
        }
        if (base_match) {
            continue;
        }
        fetched_bases[fetched_bases_count] = pkg_base->valuestring;
        fetched_bases_count++;
    }
    if (!skip_review) {
        char **viewed_bases = malloc((fetched_bases_count) * sizeof(void *));
        uint32_t viewed_bases_count = 0;
        cJSON_ArrayForEach(package, found_packages) {
            cJSON *pkg_base = cJSON_GetObjectItemCaseSensitive(package, "PackageBase");
            uint8_t base_match = 0;
            for (uint32_t idx = 0; idx < viewed_bases_count && idx < found_pkg_arrc; idx++) {
                for (uint32_t str_idx = 0; pkg_base->valuestring[str_idx] == viewed_bases[idx][str_idx]; str_idx++) {
                    if (pkg_base->valuestring[str_idx] == '\0') {
                        base_match = 1;
                        break;
                    }
                }
            }
            if (base_match) {
                continue;
            }
            viewed_bases[viewed_bases_count] = pkg_base->valuestring;
            viewed_bases_count++;
            printf("Build files for \033[1m%s\033[0m are:\n     ", pkg_base->valuestring);
            DIR *dir = opendir(pkg_base->valuestring);
            if (!dir) { 
                printf("\n");
                fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: could not list directory\n"); 
                free(viewed_bases);
                free(found_pkg_names);
                cJSON_Delete(response_body);
                return 13;
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
            printf("See \033[1m~/.cache/baurpm/%s\033[0m for more information.\n", pkg_base->valuestring);
            printf("Press Enter to continue and view PKGBUILD");
            getchar();
            printf("\n");
            chdir(pkg_base->valuestring);
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
        if (!(input_successful && prompt[0] != '\n' && (prompt[0] | 32) == 'y')) {
            printf("Installation aborted\n");
            free(found_pkg_names);
            free(fetched_bases);
            cJSON_Delete(response_body);
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
        "Please make sure all your packages are up to date or face the rick of a partial upgrade\n"
    );
    char **base_dependencies = NULL;
    uint32_t base_dependencies_amount = 0;
    cJSON_ArrayForEach(package, found_packages) {
        cJSON *pkg_name = cJSON_GetObjectItemCaseSensitive(package, "Name");
        cJSON *pkg_base = cJSON_GetObjectItemCaseSensitive(package, "PackageBase");
        uint8_t base_match = 0;
        for (uint32_t idx = 0; idx < fetched_bases_count && idx < found_pkg_arrc; idx++) {
            for (uint32_t str_idx = 0; pkg_base->valuestring[str_idx] == fetched_bases[idx][str_idx]; str_idx++) {
                if (pkg_base->valuestring[str_idx] == '\0') {
                    base_match = 1;
                    break;
                }
            }
        }
        if (base_match) {
            continue;
        }
        uint8_t different_base = 0;
        for (uint32_t idx = 0; pkg_name->valuestring[idx] != '\0'; idx++) {
            if (pkg_name->valuestring[idx] != pkg_base->valuestring[idx]) {
                different_base = 1;
                break;
            }
        }
        if (different_base) {
            chdir(pkg_base->valuestring);
            struct stat stat_info;
            int stat_status = stat(".SRCINFO", &stat_info);
            if (stat_status) {
                printf("Generating information on dependencies for package base \x1b[1m%s\x1b[0m...\n", pkg_base->valuestring);
                pid_t pid = fork();
                if (pid < 0) {
                    fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Error forking process: %s\n", strerror(errno));
                    free(found_pkg_names);
                    cJSON_Delete(response_body);
                    free(fetched_bases);
                    return 14;
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
                    cJSON_Delete(response_body);
                    free(fetched_bases);
                    return 14;
                }
                // FILE *makepkg_cmd;

                // makepkg_cmd = popen("makepkg --printsrcinfo > .SRCINFO", "r");
                // if (makepkg_cmd == NULL) {
                //     fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: popen error\n");
                //     return 14;
                // }

                // srcinfo_status_info = pclose(makepkg_cmd);
                int srcinfo_status = WEXITSTATUS(srcinfo_status_info);
                if (srcinfo_status_info == -1) {
                    fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: waitpid error -1\n");
                    free(found_pkg_names);
                    cJSON_Delete(response_body);
                    free(fetched_bases);
                    return 15;
                    
                }
                if (WIFSIGNALED(srcinfo_status_info)) {
                    fprintf(
                        stderr, "\x1b[1;33mStopping\x1b[0m: makepkg exited due to signal %d: %s\n", 
                        WTERMSIG(srcinfo_status_info), strsignal(WTERMSIG(srcinfo_status_info)));
                    free(found_pkg_names);
                    cJSON_Delete(response_body);
                    free(fetched_bases);
                    return 128+WTERMSIG(srcinfo_status_info);
                }
                if (srcinfo_status) {
                    fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: makepkg error %d\n", srcinfo_status);
                    free(found_pkg_names);
                    cJSON_Delete(response_body);
                    free(fetched_bases);
                    return 31+srcinfo_status;
                }
            }

            int srcinfo_closed;
            FILE *srcinfo_file;
            char srcinfo[PATH_MAX];

            srcinfo_file = fopen(".SRCINFO", "r");
            if (srcinfo_file == NULL) {
                fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: error opening .SRCINFO\n");
                free(found_pkg_names);
                cJSON_Delete(response_body);
                free(fetched_bases);
                return 14;
            }
            size_t srcinfo_size = fread(srcinfo, sizeof(char), PATH_MAX, srcinfo_file);

            srcinfo_closed = fclose(srcinfo_file);
            if (srcinfo_closed == -1) {
                fprintf(stderr, "\x1b[1;31mError\x1b[0m: Couldn't close .SRCINFO file\n");
            }

            char *dep_content = malloc(srcinfo_size);
            if (base_dependencies == NULL) {
                base_dependencies = malloc(PATH_MAX * found_pkg_arrc * sizeof(void *));
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
    cJSON_ArrayForEach(package, found_packages) {
        cJSON *pkg_depends = cJSON_GetObjectItemCaseSensitive(package, "Depends");
        cJSON *pkg_make_depends = cJSON_GetObjectItemCaseSensitive(package, "MakeDepends");
        if (pkg_depends && cJSON_IsArray(pkg_depends)) {
            max_depends += cJSON_GetArraySize(pkg_depends);
        }
        if (pkg_make_depends && cJSON_IsArray(pkg_make_depends)) {
            max_depends += cJSON_GetArraySize(pkg_make_depends);
        }

    }
    // printf("%u\n", max_depends);
    char **all_depends = malloc(max_depends * sizeof(void *));
    uint32_t actual_depends = base_dependencies_amount;
    for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
        all_depends[idx] = base_dependencies[idx];
    }
    cJSON_ArrayForEach(package, found_packages) {
        cJSON *pkg_depends = cJSON_GetObjectItemCaseSensitive(package, "Depends");
        cJSON *pkg_make_depends = cJSON_GetObjectItemCaseSensitive(package, "MakeDepends");
        cJSON *dependency = NULL;
        if (pkg_depends && cJSON_IsArray(pkg_depends)) {
            cJSON_ArrayForEach(dependency, pkg_depends) {
                if ((!dependency) || (!cJSON_IsString(dependency))) {
                    continue;
                }
                uint8_t already_listed = 0;
                for (uint32_t dependsi = 0; dependsi < actual_depends; dependsi++) {
                    for (uint32_t str_idx = 0; all_depends[dependsi][str_idx] == dependency->valuestring[str_idx]; str_idx++) {
                        if (dependency->valuestring[str_idx] == '\0') {
                            already_listed = 1;
                            break;
                        }
                    }
                }
                if (!already_listed) {
                    for (uint32_t idx = 0; dependency->valuestring[idx] != '\0'; idx++) {
                        if (dependency->valuestring[idx] == '<' || dependency->valuestring[idx] == '>' || dependency->valuestring[idx] == '=') {
                            dependency->valuestring[idx] = '\0';
                        }
                    }
                    all_depends[actual_depends] = dependency->valuestring;
                    actual_depends++;
                }
            }
        }
        if (pkg_make_depends && cJSON_IsArray(pkg_make_depends)) {
            cJSON_ArrayForEach(dependency, pkg_make_depends) {
                if ((!dependency) || (!cJSON_IsString(dependency))) {
                    continue;
                }
                uint8_t already_listed = 0;
                for (uint32_t dependsi = 0; dependsi < actual_depends; dependsi++) {
                    for (uint32_t str_idx = 0; all_depends[dependsi][str_idx] == dependency->valuestring[str_idx]; str_idx++) {
                        if (dependency->valuestring[str_idx] == '\0') {
                            already_listed = 1;
                            break;
                        }
                    }
                }
                if (!already_listed) {
                    for (uint32_t idx = 0; dependency->valuestring[idx] != '\0'; idx++) {
                        if (dependency->valuestring[idx] == '<' || dependency->valuestring[idx] == '>' || dependency->valuestring[idx] == '=') {
                            dependency->valuestring[idx] = '\0';
                        }
                    }
                    all_depends[actual_depends] = dependency->valuestring;
                    actual_depends++;
                }
            }
        }
    }
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
            if (base_dependencies != NULL) {
                for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                    free(base_dependencies[idx]);
                }
                free(base_dependencies);
            }
            free(found_pkg_names);
            cJSON_Delete(response_body);
            return status;
        }
        if (cJSON_IsNull(depends_response_body)) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API metadata went missing.\n");
            if (base_dependencies != NULL) {
                for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                    free(base_dependencies[idx]);
                }
                free(base_dependencies);
            }
            free(found_pkg_names);
            cJSON_Delete(response_body);
            return 9;
        }
        cJSON *found_dependencies = cJSON_GetObjectItemCaseSensitive(depends_response_body, "results");
        if (!found_dependencies) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API results went missing.\n");
            cJSON_Delete(depends_response_body);
            if (base_dependencies != NULL) {
                for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                    free(base_dependencies[idx]);
                }
                free(base_dependencies);
            }
            free(found_pkg_names);
            cJSON_Delete(response_body);
            return 9;
        }
        cJSON *found_dependency = NULL;
        // printf("%d\n", cJSON_GetArraySize(found_dependencies));
        cJSON *required_dependencies = cJSON_CreateArray();
        uint32_t required_dependencies_count = 0;
        cJSON_ArrayForEach(found_dependency, found_dependencies) {
            cJSON *dep_base = cJSON_GetObjectItemCaseSensitive(found_dependency, "PackageBase");
            uint8_t base_match = 0;
            cJSON_ArrayForEach(package, found_packages) {
                cJSON *pkg_base = cJSON_GetObjectItemCaseSensitive(package, "PackageBase");
                if ((!pkg_base) || (!cJSON_IsString(pkg_base)) || (!dep_base) || (!cJSON_IsString(dep_base))) {
                    continue;
                }
                for (uint32_t idx = 0; dep_base->valuestring[idx] == pkg_base->valuestring[idx]; idx++) {
                    if (dep_base->valuestring[idx] == '\0') {
                        base_match = 1;
                        break;
                    }
                }
            }
            if (base_match) {
                continue;
            }
            required_dependencies_count++;
            cJSON_AddItemReferenceToArray(required_dependencies, found_dependency);
        }
        if (required_dependencies_count > 0) {
            printf("Downloading dependencies...\n");
            download_and_extraction_failed = download_and_extract_pkgs(required_dependencies, required_dependencies_count);
            if (download_and_extraction_failed) {
                if (base_dependencies != NULL) {
                    for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                        free(base_dependencies[idx]);
                    }
                    free(base_dependencies);
                }
                free(found_pkg_names);
                cJSON_Delete(required_dependencies);
                cJSON_Delete(depends_response_body);
                cJSON_Delete(response_body);
                return download_and_extraction_failed;
            }
        }
        char **built_dep_bases = malloc((required_dependencies_count) * sizeof(void *));
        uint32_t built_dep_bases_count = 0;
        uint32_t dependency_install_count = 0;
        uint32_t dep_install_args_len = 0;
        uint32_t arg_max = sysconf(_SC_PAGE_SIZE)*sizeof(int)*CHAR_BIT-1;
        char **dep_install_args = malloc(sizeof(void *)*arg_max);
        for (int32_t pfx = 0; install_cmd_prefix[pfx] != NULL; pfx++) {
            dep_install_args[dep_install_args_len] = install_cmd_prefix[pfx];
            dep_install_args_len++;
        }
        uint32_t non_dyn_dep_install_args = dep_install_args_len;
        cJSON_ArrayForEach(package, required_dependencies) {
            cJSON *pkg_base = cJSON_GetObjectItemCaseSensitive(package, "PackageBase");
            uint8_t base_match = 0;
            for (uint32_t idx = 0; idx < built_dep_bases_count && idx < found_pkg_arrc; idx++) {
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
                if (base_dependencies != NULL) {
                    for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                        free(base_dependencies[idx]);
                    }
                    free(base_dependencies);
                }
                free(built_dep_bases);
                free(found_pkg_names);
                cJSON_Delete(required_dependencies);
                cJSON_Delete(depends_response_body);
                cJSON_Delete(response_body);
                return 31+errno;
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
                if (base_dependencies != NULL) {
                    for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                        free(base_dependencies[idx]);
                    }
                    free(base_dependencies);
                }
                free(built_dep_bases);
                free(found_pkg_names);
                cJSON_Delete(required_dependencies);
                cJSON_Delete(depends_response_body);
                cJSON_Delete(response_body);
                return 31+errno;
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
                    return_code = 31+ makepkg_status;
                }
                if (base_dependencies != NULL) {
                    for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                        free(base_dependencies[idx]);
                    }
                    free(base_dependencies);
                }
                free(built_dep_bases);
                free(found_pkg_names);
                cJSON_Delete(required_dependencies);
                cJSON_Delete(depends_response_body);
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
                if (base_dependencies != NULL) {
                    for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                        free(base_dependencies[idx]);
                    }
                    free(base_dependencies);
                }
                free(built_dep_bases);
                free(found_pkg_names);
                cJSON_Delete(required_dependencies);
                cJSON_Delete(depends_response_body);
                cJSON_Delete(response_body);
                return 13;
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
                            if (base_dependencies != NULL) {
                                for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                                    free(base_dependencies[idx]);
                                }
                                free(base_dependencies);
                            }
                            free(built_dep_bases);
                            free(found_pkg_names);
                            cJSON_Delete(required_dependencies);
                            cJSON_Delete(depends_response_body);
                            cJSON_Delete(response_body);
                            for (uint32_t idx = non_dyn_dep_install_args; idx < dep_install_args_len; idx++){
                                free(dep_install_args[idx]);
                            }
                            free(dep_install_args);
                            return 16;
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
                if (base_dependencies != NULL) {
                    for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                        free(base_dependencies[idx]);
                    }
                    free(base_dependencies);
                }
                for (uint32_t idx = non_dyn_dep_install_args; idx < dep_install_args_len; idx++){
                    free(dep_install_args[idx]);
                }
                free(dep_install_args);
                free(built_dep_bases);
                free(found_pkg_names);
                cJSON_Delete(required_dependencies);
                cJSON_Delete(depends_response_body);
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
                if (base_dependencies != NULL) {
                    for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                        free(base_dependencies[idx]);
                    }
                    free(base_dependencies);
                }
                free(built_dep_bases);
                free(found_pkg_names);
                cJSON_Delete(required_dependencies);
                cJSON_Delete(depends_response_body);
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
                if (base_dependencies != NULL) {
                    for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                        free(base_dependencies[idx]);
                    }
                    free(base_dependencies);
                }
                free(built_dep_bases);
                free(found_pkg_names);
                cJSON_Delete(required_dependencies);
                cJSON_Delete(depends_response_body);
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
    char **built_bases = malloc((fetched_bases_count) * sizeof(void *));
    uint32_t built_bases_count = 0;
    uint32_t install_count = 0;
    uint32_t install_args_len = 0;
    uint32_t arg_max = sysconf(_SC_PAGE_SIZE)*sizeof(int)*CHAR_BIT-1;
    char **install_args = malloc(sizeof(void *)*arg_max);
    for (int32_t pfx =0; install_cmd_prefix[pfx] != NULL; pfx++) {
        install_args[install_args_len] = install_cmd_prefix[pfx];
        install_args_len++;
    }
    uint32_t non_dyn_install_args = install_args_len;
    cJSON_ArrayForEach(package, found_packages) {
        cJSON *pkg_base = cJSON_GetObjectItemCaseSensitive(package, "PackageBase");
        uint8_t base_match = 0;
        for (uint32_t idx = 0; idx < built_bases_count && idx < found_pkg_arrc; idx++) {
            for (uint32_t str_idx = 0; pkg_base->valuestring[str_idx] == built_bases[idx][str_idx]; str_idx++) {
                if (pkg_base->valuestring[str_idx] == '\0') {
                    base_match = 1;
                    break;
                }
            }
        }
        if (base_match) {
            continue;
        }
        built_bases[built_bases_count] = pkg_base->valuestring;
        built_bases_count++;
        if (fetched_bases_count > 1) {
            printf("Making Package %d/%d \x1b[1m%s\x1b[0m\n", built_bases_count, fetched_bases_count, pkg_base->valuestring);
        } else {
            printf("Making Package \x1b[1m%s\x1b[0m\n", pkg_base->valuestring);
        }
        chdir(pkg_base->valuestring);
        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Error forking process: %s\n", strerror(errno));
            if (base_dependencies != NULL) {
                for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                    free(base_dependencies[idx]);
                }
                free(base_dependencies);
            }
            free(built_bases);
            free(found_pkg_names);
            cJSON_Delete(response_body);
            for (uint32_t idx = non_dyn_install_args; idx < install_args_len; idx++){
                free(install_args[idx]);
            }
            free(install_args);
            return 31+errno;
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
            if (base_dependencies != NULL) {
                for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                    free(base_dependencies[idx]);
                }
                free(base_dependencies);
            }
            free(built_bases);
            free(found_pkg_names);
            cJSON_Delete(response_body);
            for (uint32_t idx = non_dyn_install_args; idx < install_args_len; idx++){
                free(install_args[idx]);
            }
            free(install_args);
            return 31+errno;
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
                return_code = 31+ makepkg_status;
            }
            if (base_dependencies != NULL) {
                for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                    free(base_dependencies[idx]);
                }
                free(base_dependencies);
            }
            free(built_bases);
            free(found_pkg_names);
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
            if (base_dependencies != NULL) {
                for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                    free(base_dependencies[idx]);
                }
                free(base_dependencies);
            }
            free(built_bases);
            free(found_pkg_names);
            cJSON_Delete(response_body);
            for (uint32_t idx = non_dyn_install_args; idx < install_args_len; idx++){
                free(install_args[idx]);
            }
            free(install_args);
            return 13;
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
                        if (base_dependencies != NULL) {
                            for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                                free(base_dependencies[idx]);
                            }
                            free(base_dependencies);
                        }
                        free(built_bases);
                        free(found_pkg_names);
                        cJSON_Delete(response_body);
                        for (uint32_t idx = non_dyn_install_args; idx < install_args_len; idx++){
                            free(install_args[idx]);
                        }
                        free(install_args);
                        return 16;
                    }
                    install_count++;
                    uint32_t d_name_size;
                    for (d_name_size = 0; dir_item->d_name[d_name_size] != '\0'; d_name_size++);
                    uint32_t pkg_str_size;
                    for (pkg_str_size = 0; pkg_base->valuestring[pkg_str_size] != '\0'; pkg_str_size++);
                    char *install_file_path = malloc(d_name_size+pkg_str_size+2);
                    snprintf(install_file_path, d_name_size+pkg_str_size+2, "%s/%s", pkg_base->valuestring, dir_item->d_name);
                    install_args[install_args_len] = install_file_path;
                    install_args_len++;
                }
            }
        }
        closedir(dir);
        chdir("..");
    }
    install_args[install_args_len] = NULL;
    
    if (install_args_len-non_dyn_install_args) {
        printf("Installing \x1b[1m%d\x1b[0m packages...\n", install_count);
        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Error forking process: %s\n", strerror(errno));
            if (base_dependencies != NULL) {
                for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                    free(base_dependencies[idx]);
                }
                free(base_dependencies);
            }
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
            if (base_dependencies != NULL) {
                for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                    free(base_dependencies[idx]);
                }
                free(base_dependencies);
            }
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
            if (base_dependencies != NULL) {
                for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
                    free(base_dependencies[idx]);
                }
                free(base_dependencies);
            }
            free(built_bases);
            free(found_pkg_names);
            cJSON_Delete(response_body);
            return return_code;
        }
    }
    free(built_bases);
    printf("Installation Completed\n");
    if (base_dependencies != NULL) {
        for (uint32_t idx = 0; idx < base_dependencies_amount; idx++) {
            free(base_dependencies[idx]);
        }
        free(base_dependencies);
    }
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
        }
    }
    // todo: add proper options for this command.
    #define DB_PATH "/var/lib/pacman"
    printf("Checking for newer versions of AUR packages...\n");
    alpm_errno_t err;
    alpm_handle_t * handle = alpm_initialize("/", DB_PATH, &err);
    if (handle == NULL) {
        fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: ALPM Error %d: %s\n", err, alpm_strerror(err));
        return 18;
    }
    alpm_db_t * local_db = alpm_get_localdb(handle);
    alpm_list_t * packages = alpm_db_get_pkgcache(local_db);
    char sync_dirname[] = "sync";
    char *sync_dir_path = malloc(sizeof(DB_PATH)+sizeof(sync_dirname));
    snprintf(sync_dir_path, sizeof(DB_PATH)+sizeof(sync_dirname), "%s/%s", DB_PATH, sync_dirname);
    DIR *sync_dir = opendir(sync_dir_path);
    free(sync_dir_path);
    if (sync_dir == NULL) {
        fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: could not list db sync directory\n"); 
        alpm_release(handle);
        return 13;
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
        return 19;
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
    char **installed_names = malloc(install_count * sizeof(void *));
    char **installed_versions = malloc(install_count * sizeof(void *));
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
        snprintf(to_copy_name, pkgname_len+1, "%s", pkgname);
        installed_names[install_idx] = to_copy_name;
        char *to_copy_version = malloc(pkgver_len+1);
        snprintf(to_copy_version, pkgver_len+1, "%s", pkgver);
        installed_versions[install_idx] = to_copy_version;
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
    cJSON *response_body = find_pkg(installed_names, install_count, skip_missing, &status);
    if (status) {
        cJSON_Delete(response_body);
        // written differently as a hacky way to supress false gcc warning.
        for (uint32_t idx = 0; idx <= install_count-1; idx++) {
            /* This is the only way to both not trigger the warning and 
            prevent oob array access caused by unsigned wrap around when install_count is 0.
            Putting any form of this check anywhere outside the for loop triggers the warning
            */
            if (idx < install_count) {
                free(installed_names[idx]);
                free(installed_versions[idx]);
            }
        }
        free(installed_names);
        free(installed_versions);
        return status;
    }
    if (cJSON_IsNull(response_body)) {
        fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API metadata went missing.\n");
        for (uint32_t idx = 0; idx < install_count; idx++) {
            free(installed_names[idx]);
            free(installed_versions[idx]);
        }
        free(installed_names);
        free(installed_versions);
        return 9;
    }
    cJSON *found_packages = cJSON_GetObjectItemCaseSensitive(response_body, "results");
    if (!found_packages) {
        cJSON_Delete(response_body);
        fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: API results went missing.\n");
        for (uint32_t idx = 0; idx < install_count; idx++) {
            free(installed_names[idx]);
            free(installed_versions[idx]);
        }
        free(installed_names);
        free(installed_versions);
        return 9;
    }
    if (!cJSON_GetArraySize(found_packages)) {
        cJSON_Delete(response_body);
        fprintf(stderr, "\x1b[1;31mError\x1b[0m: No packages to install, exiting...\n");
        for (uint32_t idx = 0; idx < install_count; idx++) {
            free(installed_names[idx]);
            free(installed_versions[idx]);
        }
        free(installed_names);
        free(installed_versions);
        return 2;
    }
    uint32_t found_pkg_arrc = cJSON_GetArraySize(found_packages);
    const cJSON *package;
    uint32_t pkg_num = 0;
    // Note: this will share addresses from installed_names so no need to free() each element or will result in double free.
    char **needs_update = malloc(found_pkg_arrc * sizeof(void *));
    cJSON *package_data = cJSON_CreateArray();
    uint32_t outdated_count = 0;
    cJSON_ArrayForEach(package, found_packages) {
        cJSON *name = cJSON_GetObjectItemCaseSensitive(package, "Name");
        cJSON *version = cJSON_GetObjectItemCaseSensitive(package, "Version");
        if (name && name->valuestring && version && cJSON_IsString(version)) {
            uint32_t outdated = 1;
            uint32_t missing = 1;
            for (uint32_t idx = 0; installed_names[pkg_num][idx] == name->valuestring[idx]; idx++) {
                if (name->valuestring[idx] == '\0') {
                    missing = 0;
                    break;
                }
            }
            if (missing) {
                pkg_num++;
            }
            for (uint32_t idx = 0; installed_versions[pkg_num][idx] == version->valuestring[idx]; idx++) {
                if (version->valuestring[idx] == '\0') {
                    outdated = 0;
                    break;
                }
            }
            if (outdated) {
                // Note: shares addresses from installed_names
                needs_update[outdated_count] = installed_names[pkg_num];
                cJSON_AddItemReferenceToArray(package_data, (cJSON *) package);
                outdated_count++;
            }
        }
        pkg_num++;
    }
    if (!outdated_count) {
        printf("\x1b[1mAll installed AUR packages are up to date\x1b[0m\n");
        // free everything
        cJSON_Delete(response_body);
        for (uint32_t idx = 0; idx < install_count; idx++) {
            // printf("%d %s %s\n", idx, installed_names[idx], installed_versions[idx]);
            free(installed_names[idx]);
            free(installed_versions[idx]);
        }
        cJSON_Delete(package_data);
        free(needs_update);
        free(installed_names);
        free(installed_versions);
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
    if (!(input_successful && prompt[0] != '\n' && (prompt[0] | 32) == 'y')) {
        // free everything
        cJSON_Delete(response_body);
        for (uint32_t idx = 0; idx < install_count; idx++) {
            // printf("%d %s %s\n", idx, installed_names[idx], installed_versions[idx]);
            free(installed_names[idx]);
            free(installed_versions[idx]);
        }
        cJSON_Delete(package_data);
        free(needs_update);
        free(installed_names);
        free(installed_versions);
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
                for (uint32_t idx = 0; idx < install_count; idx++) {
                    free(installed_names[idx]);
                    free(installed_versions[idx]);
                }
                cJSON_Delete(package_data);
                free(needs_update);
                free(installed_names);
                free(installed_versions);
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
                for (uint32_t idx = 0; idx < install_count; idx++) {
                    free(installed_names[idx]);
                    free(installed_versions[idx]);
                }
                cJSON_Delete(package_data);
                free(needs_update);
                free(installed_names);
                free(installed_versions);
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
                for (uint32_t idx = 0; idx < install_count; idx++) {
                    // printf("%d %s %s\n", idx, installed_names[idx], installed_versions[idx]);
                    free(installed_names[idx]);
                    free(installed_versions[idx]);
                }
                cJSON_Delete(package_data);
                free(needs_update);
                free(installed_names);
                free(installed_versions);
                return 128+WTERMSIG(keyring_status);
            }
            if (keyring_failed) {
                fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Pacman failed with exit code %d\n", keyring_failed);
                cJSON_Delete(response_body);
                for (uint32_t idx = 0; idx < install_count; idx++) {
                    free(installed_names[idx]);
                    free(installed_versions[idx]);
                }
                cJSON_Delete(package_data);
                free(needs_update);
                free(installed_names);
                free(installed_versions);
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
            for (uint32_t idx = 0; idx < install_count; idx++) {
                free(installed_names[idx]);
                free(installed_versions[idx]);
            }
            free(needs_update);
            free(installed_names);
            free(installed_versions);
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
            for (uint32_t idx = 0; idx < install_count; idx++) {
                free(installed_names[idx]);
                free(installed_versions[idx]);
            }
            free(needs_update);
            free(installed_names);
            free(installed_versions);
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
            for (uint32_t idx = 0; idx < install_count; idx++) {
                // printf("%d %s %s\n", idx, installed_names[idx], installed_versions[idx]);
                free(installed_names[idx]);
                free(installed_versions[idx]);
            }
            cJSON_Delete(package_data);
            free(needs_update);
            free(installed_names);
            free(installed_versions);
            return 128+WTERMSIG(pacman_status);
        }
        if (pacman_failed) {
            fprintf(stderr, "\x1b[1;31mFatal\x1b[0m: Pacman failed with exit code %d\n", pacman_failed);
            cJSON_Delete(package_data);
            cJSON_Delete(response_body);
            for (uint32_t idx = 0; idx < install_count; idx++) {
                // printf("%d %s %s\n", idx, installed_names[idx], installed_versions[idx]);
                free(installed_names[idx]);
                free(installed_versions[idx]);
            }
            free(needs_update);
            free(installed_names);
            free(installed_versions);
            return 64;
        }
    }
    uint8_t return_code = command_i(options, needs_update, outdated_count, package_data);
    cJSON_Delete(package_data);
    cJSON_Delete(response_body);
    for (uint32_t idx = 0; idx < install_count; idx++) {
        // printf("%d %s %s\n", idx, installed_names[idx], installed_versions[idx]);
        free(installed_names[idx]);
        free(installed_versions[idx]);
    }
    free(needs_update);
    free(installed_names);
    free(installed_versions);
    // printf("%u\n", install_count);
    return return_code;
}

int command_u(char *options, char *arguments[], int32_t arg_len, cJSON *_) {
    cJSON_Delete(_);
    (void)(options); 
    (void)(arguments);
    (void)(arg_len);
    printf("cached upgrade command has been run\n");
    return 0;
}

int command_v(char *options, char *arguments[], int32_t arg_len, cJSON *_) {
    cJSON_Delete(_);
    (void)(options); 
    (void)(arguments);
    (void)(arg_len);
    printf("v command has been run\n");
    printf("This is the testing command\n");
    char *unit_buffer = byte_units(-1);
    printf("%s\n", unit_buffer);
    free(unit_buffer);
    // char *test1[3] = {"test1", "test2", "test3"};
    // char *test2[1] = {"test3"};
    // uint32_t test1c = 3;
    // uint32_t test2c = 1;
    // char **missing_pkgs = find_missing(test1, test1c, test2, test2c);
    // uint32_t missing_size = test1c-test2c;
    // printf("calculated size: %u\n", missing_size);
    // for (uint32_t arri = 0; arri < missing_size; arri++) {
    //     printf("%s\n", missing_pkgs[arri]);
    // }
    // free(missing_pkgs);
    return 0;
}

int command_a(char *options, char *arguments[], int32_t arg_len, cJSON *package_data) {
    if (cJSON_IsNull(package_data)) {
        cJSON_Delete(package_data);
    }
    (void)(options); 
    (void)(arguments);
    (void)(arg_len);
    printf("cached install command has been run\n");
    return 0;
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
        char name_lookup[] = { 'h', 'g', 'i', 'c', 'u', 'v', 'a' };
        stdcall function_lookup[] = { command_h, command_g, command_i, command_c, command_u, command_v, command_a };
        uint8_t cmd_idx;
        for (cmd_idx = 0; cmd_idx < 7; cmd_idx++) {
            if ((cmd_name | 32) == name_lookup[cmd_idx]) {
                return_code = function_lookup[cmd_idx](cmd_opts, command_args, argc-2, cJSON_CreateNull());
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
