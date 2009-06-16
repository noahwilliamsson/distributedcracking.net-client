#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

// struct db_main 
#include "loader.h"

// log_event()
#include "logger.h"

// extern struct options *
#include "options.h"

// path_expand()
#include "path.h"

#ifdef __APPLE__
# include <sys/types.h>
# include <sys/sysctl.h>
#endif

#ifdef __CYGWIN32__
# include <windows.h>
#endif

#include "webapi.h"


static CURL *ch;

// In memory received data
static char *webapi_data_ptr;
static size_t webapi_data_len;
// Node authentication cookie
static char webapi_cookie[32 + 1];

unsigned int packet_id;
unsigned int packet_job_id;
unsigned long long packet_rounds;
char packet_state[256];
char job_name[512];
char *webapi_last_error_msg = NULL;

static int webapi_authcookie_save(void) {
#ifdef __CYGWIN32__
	
	return webapi_registry_set(WEBAPI_REG_KEYNAME, webapi_cookie);
#else
	FILE *fd;
	
	if((fd = fopen(path_expand("$JOHN/cookie"), "wt")) == NULL)
		return -1;

	fprintf(fd, "%s", webapi_cookie);
	fclose(fd);
	
	return 0;
#endif
}


static int webapi_authcookie_load(void) {
#ifdef __CYGWIN32__
	char *p;
	
	if((p = webapi_registry_get(WEBAPI_REG_KEYNAME)) == NULL)
		return -1;
	
	if(strlen(p) == 0)
		return -1;

	memcpy(webapi_cookie, p, sizeof(webapi_cookie) - 1);
	
	return 0;
#else
	FILE *fd;
	
	if((fd = fopen(path_expand("$JOHN/cookie"), "r")) == NULL)
		return -1;

	fread(webapi_cookie, sizeof(webapi_cookie) -1, sizeof(char), fd);
	fclose(fd);
	
	return 0;	
#endif
}


/*
 * Extract CPU model name
 * XXX - Extract number of CPUs too
 *
 */
static char *webapi_cpuinfo(void) {
	static char buf[512] = { "Unknown CPU" };
#ifdef __APPLE__
	size_t len = sizeof(buf) - 1;

	sysctlbyname("machdep.cpu.brand_string", buf, &len, NULL, 0);
#else
	FILE *fd;
	char tmp[512];

	if((fd = fopen("/proc/cpuinfo", "r")) != NULL) {
		while(fgets(tmp, sizeof(tmp) - 1, fd)) {
			if(sscanf(tmp, "model name\t: %[^\n]", buf) == 1)
				break;
		}
		fclose(fd);
	}
	
#endif

	return buf;
}


int webapi_init(void) {
	
	if((ch = curl_easy_init()) == NULL
		|| curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1) != CURLE_OK
		|| curl_easy_setopt(ch, CURLOPT_USERAGENT, WEBAPI_UA) != CURLE_OK
		|| curl_easy_setopt(ch, CURLOPT_ENCODING, "") != CURLE_OK
		|| curl_easy_setopt(ch, CURLOPT_COOKIEFILE, "") != CURLE_OK 
		|| curl_easy_setopt(ch, CURLOPT_NOSIGNAL, 1) != CURLE_OK 
		|| curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 1) != CURLE_OK 
		|| curl_easy_setopt(ch, CURLOPT_SSL_VERIFYHOST, 2) != CURLE_OK 
		|| curl_easy_setopt(ch, CURLOPT_CAINFO, strdup(path_expand("$JOHN/ca.pem"))) != CURLE_OK) {
		fprintf(stderr, "webapi: cURL initalization failed.\n");
		log_event("webapi: cURL initalization failed.\n");

		if(ch)
			curl_easy_cleanup(ch);

		return -1;
	}
	
	
	webapi_authcookie_load();
	
	return 0;
}



static int webapi_receive(void *ptr, size_t size, size_t nmemb, void *private) {
	char *reallocated;

	if((reallocated = realloc(webapi_data_ptr, webapi_data_len + size * nmemb + 1)) == NULL) {

		log_event("webapi_receive(): realloc() failed; had %d bytes of memory, requested %d bytes more.\n", webapi_data_len + 1, size * nmemb);

		return -1;
	}

	webapi_data_ptr = reallocated;		
	memcpy(webapi_data_ptr + webapi_data_len, ptr, size * nmemb);
	webapi_data_len += size * nmemb;
	
	webapi_data_ptr[webapi_data_len] = '\0';
	
	return size * nmemb;
}


static void webapi_receive_reset(void) {
	webapi_data_len = 0;

	if(webapi_data_ptr) {
		free(webapi_data_ptr);
		webapi_data_ptr = NULL;
	}
}

/*
 * Dumps error message and returns API error code or -1 if none found
 *
 */
static int webapi_dump_error(char *prefix) {
	int webapi_errno = -1;
	char *p;
	
	
	if(webapi_last_error_msg) {
		free(webapi_last_error_msg);
		webapi_last_error_msg = NULL;
	}
	
	
	
	if(webapi_data_ptr == NULL || webapi_data_len == 0) {
		webapi_last_error_msg = (char *)calloc(strlen(prefix) + 100, sizeof(char));
		sprintf(webapi_last_error_msg, "%s: Nothing received\n", prefix);
	}
	else if(sscanf(webapi_data_ptr, "%d", &webapi_errno) == 1) {
		if((p = strchr(webapi_data_ptr, ' ')) != NULL)
			p++;

		webapi_last_error_msg = (char *)calloc(strlen(prefix) + (p? strlen(p): 0) + 256, sizeof(char));
			
		switch(webapi_errno) {
			case 100:
				sprintf(webapi_last_error_msg, "%s: success, but unexpected data received: [%s]\n", prefix, p? p: "<no additional info>");
				break;
	
			case 150:
				sprintf(webapi_last_error_msg, "%s: %s\n", prefix, p? p: "<no additional info>");
				break;
	
			case 200:
				sprintf(webapi_last_error_msg, "%s: authentication failed: %s\n", prefix, p? p: "<no additional info>");
				break;
				
			case 300:
				sprintf(webapi_last_error_msg, "%s: database error: %s\n", prefix, p? p: "<no additional info>");
				break;

			case 400:
				sprintf(webapi_last_error_msg, "%s: You need to upgrade the client (%s is not allowed anymore).\nDownload the latest version from " WEBAPI_URL "download", prefix, WEBAPI_VERSION);
				
			case 500:
			default:
				sprintf(webapi_last_error_msg, "%s: misc error: %s\n", prefix, p? p: "<no additional info>");
				break;
		}
	}
	else {
		webapi_last_error_msg = (char *)calloc(strlen(prefix) + (webapi_data_ptr && *webapi_data_ptr? strlen(webapi_data_ptr): 0) + 100, sizeof(char));
		sprintf(webapi_last_error_msg, "%s: invalid response: %s\n", prefix, webapi_data_ptr);
	}

	log_event("%s", webapi_last_error_msg);
#ifdef __CYGWIN32__
	if(webapi_errno != 150)
			MessageBox(0, webapi_last_error_msg, "DistributedCracking.net: An error occured", MB_OK);
#else
		fprintf(stderr, "%s", webapi_last_error_msg);
#endif
	
	return webapi_errno;
}


/*
 * Register a node with the network
 *
 */
int webapi_register(char *username, char *password, char *ciphers) {
	char *postdata = NULL;
	char *cpuinfo = NULL;
	int len;
	int retries, webapi_sleep = WEBAPI_DELAY_INIT;
	int register_error = 0, ret = -1;
	CURLcode cc;
		
	if((username = curl_easy_escape(ch, username, 0)) == NULL
		|| (password = curl_easy_escape(ch, password, 0)) == NULL
		|| (ciphers = curl_easy_escape(ch, ciphers, 0)) == NULL
		|| (cpuinfo = curl_easy_escape(ch, webapi_cpuinfo(), 0)) == NULL) {
		goto out;
	}
	
	/* u=user&p=pass&ciphers=cipherlist&cpuinfo=cpuinfo */
	len = 2 + strlen(username) + 3 + strlen(password) + 9 + strlen(ciphers) + 9 + strlen(cpuinfo) + 1;

	if((postdata = (char *)calloc(len, sizeof(char))) == NULL) {
		goto out;
	}

	sprintf(postdata, "u=%s&p=%s&ciphers=%s&cpuinfo=%s", username, password, ciphers, cpuinfo);

	// Request data
	curl_easy_setopt(ch, CURLOPT_POSTFIELDS, postdata);
	curl_easy_setopt(ch, CURLOPT_URL, WEBAPI_URL "register.php");
	curl_easy_setopt(ch, CURLOPT_STDERR, stderr);


	// Receive data to memory
	curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, webapi_receive);

	
	for(retries = 0; retries < WEBAPI_RETRIES; retries++) {
		// Prevent hammering
		// XXX - Doesn't work due to signaling
		if(retries > 0) {
			webapi_sleep *= 2;
			if(webapi_sleep > WEBAPI_DELAY_MAX)
				webapi_sleep = WEBAPI_DELAY_MAX;

			sleep(webapi_sleep);
		}


		// Free and reset received data memory
		webapi_receive_reset();

		if((cc = curl_easy_perform(ch)) != CURLE_OK) {
			fprintf(stderr, "webapi: register: failed: %s\n", curl_easy_strerror(cc));
			log_event("webapi: register: failed: %s\n", curl_easy_strerror(cc));
			continue;
		}

		if(webapi_data_ptr
			&& sscanf(webapi_data_ptr, "100 %32[0-9a-f]", webapi_cookie) == 1) {
				if(strlen(webapi_cookie) == 32)
					break;
		}

		// Bail out on authentication failures
		register_error = webapi_dump_error("webapi: register");
		if(register_error == WEBAPI_ERROR_AUTH || register_error == WEBAPI_ERROR_UPGRADE)
			goto out;
	}
	
	
	if(retries != WEBAPI_RETRIES) {
#ifdef __CYGWIN32__
		MessageBox(0, "Node successfully registered", "DistributedCracking.net", MB_OK);
#else
		fprintf(stdout, "webapi: Node successfully registered.\n");
#endif
		log_event("Node successfully registered. Credentials stored in cookie jar.\n");
		ret = 0;
		
		webapi_authcookie_save();
	}
	
	
out:
	if(username)
		curl_free(username);
	
	if(password)
		curl_free(password);
		
	if(ciphers)
		curl_free(ciphers);
	
	if(cpuinfo)
		curl_free(cpuinfo);
	
	if(postdata)
		free(postdata);
	
	webapi_receive_reset();
	
	return ret;		

}


int webapi_login(void) {
	char *postdata = NULL;
	int retries, webapi_sleep = WEBAPI_DELAY_INIT;
	int webapi_error_code;
	int login_error, ret = -1;
	CURLcode cc;

	if(strlen(webapi_cookie) != 32) {
		fprintf(stderr, "webapi: login: invalid auth cookie\n");
		log_event("webapi: login: invalid auth cookie '%s'\n", webapi_cookie);
		return -1;
	}
	
	/* a=<32 bytes authcookie> */
	if((postdata = (char *)calloc(2 + 32 + 1, sizeof(char))) == NULL)
		return -1;

	sprintf(postdata, "a=%s", webapi_cookie);

	// Request data
	curl_easy_setopt(ch, CURLOPT_POSTFIELDS, postdata);
	curl_easy_setopt(ch, CURLOPT_URL, WEBAPI_URL "login.php");

	// Receive data in memory
	curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, webapi_receive);

	
	for(retries = 0; retries < WEBAPI_RETRIES; retries++) {
		// Prevent hammering
		// XXX - Doesn't work due to signaling
		if(retries > 0) {
			webapi_sleep *= 2;
			if(webapi_sleep > WEBAPI_DELAY_MAX)
				webapi_sleep = WEBAPI_DELAY_MAX;

			sleep(webapi_sleep);
		}


		// Free and reset received data memory
		webapi_receive_reset();

		if((cc = curl_easy_perform(ch)) != CURLE_OK) {
			fprintf(stderr, "webapi: login: failed: %s\n", curl_easy_strerror(cc));
			log_event("webapi: login: failed: %s\n", curl_easy_strerror(cc));
			continue;
		}

		
		if(webapi_data_ptr && sscanf(webapi_data_ptr, "%d", &webapi_error_code) == 1) {
				if(webapi_error_code == 100)
					break;
		}

		// Bail out on authentication failures
		login_error = webapi_dump_error("webapi: login");
		if(login_error == WEBAPI_ERROR_AUTH || login_error == WEBAPI_ERROR_UPGRADE)
			goto out;
	}
	
	
	if(retries != WEBAPI_RETRIES) {
#ifndef __CYGWIN32__
		fprintf(stdout, "webapi:%s\n", strchr(webapi_data_ptr, ' '));
#endif
		log_event("Node successfully logged in:%s",  strchr(webapi_data_ptr, ' '));
		ret = 0;
	}
	
	
out:
	if(postdata)
		free(postdata);
	
	webapi_receive_reset();
	
	return ret;		
}


int webapi_fetch_work(struct db_main *database, char *attack_mode, char *attack_options) {
	int retries, webapi_sleep = WEBAPI_DELAY_INIT;
	int webapi_error_code;
	int ret = -1;
	CURLcode cc;
	char url[256];
	char *passwd_ptr = NULL, *nextline;
	
	printf("[webapi] Fetching work..\r"); fflush(stdout);
	if(strlen(webapi_cookie) != 32) {
		fprintf(stderr, "webapi: fetch work: invalid auth cookie\n");
		log_event("webapi: fetch work: invalid auth cookie '%s'\n", webapi_cookie);
		return -1;
	}
	

	// Request data
	sprintf(url, "%sfetch-job.php", WEBAPI_URL);
	curl_easy_setopt(ch, CURLOPT_URL, url);
	curl_easy_setopt(ch, CURLOPT_HTTPGET, 1);


	// Receive data in memory
	curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, webapi_receive);

	
	for(retries = 0; retries < WEBAPI_RETRIES; retries++) {
		// Prevent hammering
		// XXX - Doesn't work due to signaling
		if(retries > 0) {
			webapi_sleep *= 2;
			if(webapi_sleep > WEBAPI_DELAY_MAX)
				webapi_sleep = WEBAPI_DELAY_MAX;

			sleep(webapi_sleep);
		}


		// Free and reset received data memory
		webapi_receive_reset();

		if((cc = curl_easy_perform(ch)) != CURLE_OK) {
			fprintf(stderr, "webapi: fetch work: failed: %s\n", curl_easy_strerror(cc));
			log_event("webapi: fetch work: failed: %s\n", curl_easy_strerror(cc));
			continue;
		}

		memset(attack_mode, 0, 16);
		memset(attack_options, 0, 16);
		if(webapi_data_ptr
			&& sscanf(webapi_data_ptr, "%d %15s %15s %u %255[^\n]",
				&webapi_error_code, attack_mode, attack_options, &packet_job_id, job_name) == 5) {
			
			if(webapi_error_code == 100
				&& (passwd_ptr = strchr(webapi_data_ptr, '\n')) != NULL) {
				passwd_ptr++;
				break;
			}
		}

		// Bail out on authentication failures
		if(webapi_dump_error("webapi: fetch work") == WEBAPI_ERROR_AUTH)
			goto out;
	}
	
	
	if(retries != WEBAPI_RETRIES) {
		printf("[webapi] Job: %s (id: %u)\n", job_name, packet_job_id);
		printf("[webapi] Attack mode: %s (%s)\n", attack_mode, attack_options);

		// Don't waste memory on login names		
		options.loader.flags &= ~DB_LOGIN;
		
		// Initalize password database
		ldr_init_database(database, &options.loader);

		// Load password file
		do {
			if((nextline = strchr(passwd_ptr, '\n')) != NULL)
				*nextline++ = 0;
				
			if(*passwd_ptr)
				ldr_load_pw_line(database, passwd_ptr);
		} while((passwd_ptr = nextline) != NULL);


		// More or less ripped from john_load() in john.c
		if(database->password_count) {
			log_init(LOG_NAME, NULL, options.session);
		}

		ldr_fix_database(database);
		if(database->password_count) {
			char buf[256];
			sprintf(buf, "Loaded %d unique hash%s with %d different salt%s (%s [%s])",
				database->password_count,
				database->password_count != 1? "es": "",
				database->salt_count,
				database->salt_count != 1? "s": "",
				database->format->params.format_name,
				database->format->params.algorithm_name);
			printf("%s\n", buf);
			log_event("%s", buf);
		} else {
			log_discard();
			puts("No password hashes loaded");
			goto out;
		}

		if(!database->salts) {
			fprintf(stderr, "webapi: fetch work: Argh.. database.salts is zero!\n");
			goto out;
		}
		
		ret = 0;
	}
	
	
	
out:
	webapi_receive_reset();
	
	return ret;		
}


int webapi_fetch_state(void) {
	int retries, webapi_sleep = WEBAPI_DELAY_INIT;
	int webapi_error_code;
	int ret = -1;
	CURLcode cc;
	char url[256];
	
	printf("[webapi] Fetching state..\r");
	fflush(stdout);
	if(strlen(webapi_cookie) != 32) {
		fprintf(stderr, "webapi: fetch state: invalid auth cookie\n");
		log_event("webapi: fetch state: invalid auth cookie '%s'\n", webapi_cookie);
		return -1;
	}
	
	// Request data
	sprintf(url, "%sfetch-state.php?j=%u", WEBAPI_URL, packet_job_id);
	curl_easy_setopt(ch, CURLOPT_URL, url);
	curl_easy_setopt(ch, CURLOPT_HTTPGET, 1);


	// Receive data in memory
	curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, webapi_receive);

	
	for(retries = 0; retries < WEBAPI_RETRIES; retries++) {
		// Prevent hammering
		// XXX - Doesn't work due to signaling
		if(retries > 0) {
			webapi_sleep *= 2;
			if(webapi_sleep > WEBAPI_DELAY_MAX)
				webapi_sleep = WEBAPI_DELAY_MAX;

			sleep(webapi_sleep);
		}


		// Free and reset received data memory
		webapi_receive_reset();

		if((cc = curl_easy_perform(ch)) != CURLE_OK) {
			fprintf(stderr, "webapi: fetch state: failed: %s\n", curl_easy_strerror(cc));
			log_event("webapi: fetch state: failed: %s\n", curl_easy_strerror(cc));
			continue;
		}

		if(webapi_data_ptr
			&& sscanf(webapi_data_ptr, "%d %u %llu %255[^\n]",
						&webapi_error_code, &packet_id, &packet_rounds, packet_state) == 4) {
			
			packet_state[sizeof(packet_state) - 1] = 0;
			if(webapi_error_code == 100)
				break;
		}

		// Bail out on authentication failures
		webapi_error_code = webapi_dump_error("webapi: fetch state");
		if(webapi_error_code == WEBAPI_ERROR_AUTH || webapi_error_code == WEBAPI_ERROR_RESTART)
			goto out;
	}
	
	
	if(retries != WEBAPI_RETRIES) {
		printf("[webapi] Got packet %u with %llu rounds (state %s)\n", packet_id, packet_rounds, packet_state);
		sleep(1);
		ret = 0;
	}
	
	
out:
	webapi_receive_reset();
	
	return ret;		
}



int webapi_packet_done(void) {
	int retries, webapi_sleep = WEBAPI_DELAY_INIT;
	int ret = -1;
	CURLcode cc;
	char url[256];
	
	printf("[webapi] Submitting packet as DONE..\r"); fflush(stdout);
	if(strlen(webapi_cookie) != 32) {
		fprintf(stderr, "webapi: packet done: invalid auth cookie\n");
		log_event("webapi: packet done: invalid auth cookie '%s'\n", webapi_cookie);
		return -1;
	}
	

	// Request data
	sprintf(url, "%ssubmit-packet.php?j=%u&p=%u\n", WEBAPI_URL, packet_job_id, packet_id);
	curl_easy_setopt(ch, CURLOPT_URL, url);
	curl_easy_setopt(ch, CURLOPT_HTTPGET, 1);


	// Receive data in memory
	curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, webapi_receive);

	
	for(retries = 0; retries < WEBAPI_RETRIES; retries++) {
		// Prevent hammering
		// XXX - Doesn't work due to signaling
		if(retries > 0) {
			webapi_sleep *= 2;
			if(webapi_sleep > WEBAPI_DELAY_MAX)
				webapi_sleep = WEBAPI_DELAY_MAX;

			sleep(webapi_sleep);
		}


		// Free and reset received data memory
		webapi_receive_reset();

		if((cc = curl_easy_perform(ch)) != CURLE_OK) {
			fprintf(stderr, "webapi: fetch state: failed: %s\n", curl_easy_strerror(cc));
			log_event("webapi: fetch state: failed: %s\n", curl_easy_strerror(cc));
			continue;
		}

		if(webapi_data_ptr && !strncmp(webapi_data_ptr, "100", 3)) {
			break;
		}

		// Bail out on authentication failures
		if(webapi_dump_error("webapi: fetch state") == WEBAPI_ERROR_AUTH)
			goto out;
	}
	
	
	if(retries != WEBAPI_RETRIES) {
		printf("[webapi] Got packet %u with %llu rounds (state %s)\n", packet_id, packet_rounds, packet_state);
		sleep(1);
		ret = 0;
	}
	
	
out:
	webapi_receive_reset();
	
	packet_id = 0;
	packet_job_id = 0;
	packet_rounds = 0;
	
	memset(&inc_rec_state, 0, sizeof(inc_rec_state));
	*job_name = 0;
	if(webapi_last_error_msg)
		*webapi_last_error_msg = 0;
	
	return ret;		
}


int webapi_report_guess(char *hash, char *key) {
	int retries, webapi_sleep = WEBAPI_DELAY_INIT;
	int ret = -1;
	CURLcode cc;
	char *postdata = NULL;
	
	if(strlen(webapi_cookie) != 32) {
		fprintf(stderr, "webapi: report guess: invalid auth cookie\n");
		log_event("webapi: report guess: invalid auth cookie '%s'\n", webapi_cookie);
		return -1;
	}


	if((hash = curl_easy_escape(ch, hash, 0)) == NULL ||
		(key = curl_easy_escape(ch, key, 0)) == NULL)
		goto out;


	if((postdata = (char *)calloc(100, sizeof(char))) == NULL)
		return -1;

	sprintf(postdata, "j=%u&pot[]=%s:%s", packet_job_id, hash, key);

	// Request data
	curl_easy_setopt(ch, CURLOPT_POSTFIELDS, postdata);
	curl_easy_setopt(ch, CURLOPT_URL, WEBAPI_URL "submit-hashes.php");


	// Receive data in memory
	curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, webapi_receive);

	
	for(retries = 0; retries < WEBAPI_RETRIES; retries++) {
		// Prevent hammering
		// XXX - Doesn't work due to signaling
		if(retries > 0) {
			webapi_sleep *= 2;
			if(webapi_sleep > WEBAPI_DELAY_MAX)
				webapi_sleep = WEBAPI_DELAY_MAX;

			sleep(webapi_sleep);
		}


		// Free and reset received data memory
		webapi_receive_reset();

		if((cc = curl_easy_perform(ch)) != CURLE_OK) {
			fprintf(stderr, "webapi: report guess: failed: %s\n", curl_easy_strerror(cc));
			log_event("webapi: report guess: failed: %s\n", curl_easy_strerror(cc));
			continue;
		}

		if(webapi_data_ptr && !strncmp(webapi_data_ptr, "100", 3)) {
			break;
		}

		// Bail out on authentication failures
		if(webapi_dump_error("webapi: report guess") == WEBAPI_ERROR_AUTH)
			goto out;
	}
	
	
	if(retries != WEBAPI_RETRIES) {
		ret = 0;
	}
	
	
out:
	if(postdata)
		free(postdata);
		
	webapi_receive_reset();
	
	return ret;		
}



/*
void webapi_free_internal(struct db_main *db) {

	// init db each time:
	db->salt_count = db->password_count = db->guess_count = 0;
	db->format = NULL;



	MEM_FREE(db->options);
	MEM_FREE(db->cracked_hash);
	MEM_FREE(db->salt_hash);
	MEM_FREE(db->password_hash);
	
	struct list_entry *current = list->head, *next = NULL;
	do {
		if(current)
			next = current->next;
		MEM_FREE(current);
	} while((current = next));


	db->loaded = 0;
	if(db->plaintexts) {
	db->plaintext = NULL;
	
}
*/



#ifdef __CYGWIN32__
char *webapi_registry_get(char *name) {
	HKEY k;
	static char buf[128];
	DWORD sz = sizeof(buf) - 1, ret;
	
	if(RegCreateKeyEx(HKEY_CURRENT_USER, WEBAPI_REG_SUBKEY, 0, NULL, 0, KEY_READ, NULL, &k, NULL) != ERROR_SUCCESS)
		return NULL;
	
	ret = RegQueryValueEx(k, name, 0, NULL, buf, &sz);
	RegCloseKey(k);
	
	if(ret != ERROR_SUCCESS)
		return NULL;
	
	return buf;	
}


int webapi_registry_delete(char *name) {
	HKEY k;
	DWORD ret;
	
	if(RegCreateKeyEx(HKEY_CURRENT_USER, WEBAPI_REG_SUBKEY, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL) != ERROR_SUCCESS)
		return -1;
	
	ret = RegDeleteValue(k, name);
	RegCloseKey(k);
	
	if(ret != ERROR_SUCCESS)
		return -1;
	
	return 0;	
}


int webapi_registry_set(char *name, char *value) {
	HKEY k;

	if(RegCreateKeyEx(HKEY_CURRENT_USER, WEBAPI_REG_SUBKEY, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL) != ERROR_SUCCESS)
		return -1;
	
	RegSetValueEx(k, name, 0, REG_SZ, value, strlen(value));
	RegCloseKey(k);
	
	return 0;
}
#endif
