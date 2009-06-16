#define WEBAPI_URL				"https://distributedcracking.net/api/"
#define WEBAPI_VERSION			"0.9-20080715"
#define WEBAPI_UA				"jtr/webapi " WEBAPI_VERSION
#define WEBAPI_COOKIE_JAR		"webapi.cookie"

#define WEBAPI_RETRIES			100
#define WEBAPI_DELAY_INIT		2
#define WEBAPI_DELAY_MAX		600

#define WEBAPI_ERROR_SUCCESS		100
#define WEBAPI_ERROR_RESTART		150
#define WEBAPI_ERROR_AUTH		200
#define WEBAPI_ERROR_DB			300
#define WEBAPI_ERROR_UPGRADE		400
#define WEBAPI_ERROR_MISC		500


// curl_easy_escape() was added in cURL 7.15.4
#ifndef curl_easy_escape
#define curl_easy_escape(ch, url, len) curl_escape(url, len)
#endif


int webapi_init(void);
int webapi_register(char *username, char *password, char *ciphers);
int webapi_login(void);
int webapi_fetch_work(struct db_main *, char *attack_mode, char *attack_options);
int webapi_fetch_state(void);
int webapi_packet_done(void);
int webapi_report_guess(char *hash, char *key);

// This isn't exported by the standard john the ripper
void ldr_load_pw_line(struct db_main *db, char *line);

/*
 * Defined in webapi.c
 */
extern char job_name[];
extern unsigned int packet_id;
extern unsigned long long packet_rounds;
extern char packet_state[];
extern char *webapi_last_error_msg;

/*
 * Defined in inc.c
 * To be able to resume incremental cracking
 *
 */
typedef struct {
	int initialized;
	int pos;
	int numbers_cache;
	int cc_0, cc_1, cc_2;
	unsigned long long words_requested;
	unsigned long long words_generated;
	char key_i[PLAINTEXT_BUFFER_SIZE];
} inc_key_loop_state;
extern inc_key_loop_state inc_rec_state;


#ifdef __CYGWIN32__

#define WEBAPI_REG_SUBKEY	"Software\\DistributedCracking.net"
#define WEBAPI_REG_KEYNAME	"Authcookie"

int webapi_registry_set(char *name, char *value);
int webapi_registry_delete(char *name);
char *webapi_registry_get(char *name);
#endif
