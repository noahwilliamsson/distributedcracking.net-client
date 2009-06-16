/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2004,2006 by Solar Designer
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "path.h"
#include "memory.h"
#include "list.h"
#include "tty.h"
#include "signals.h"
#include "common.h"
#include "formats.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "options.h"
#include "config.h"
#include "bench.h"
#include "charset.h"
#include "single.h"
#include "wordlist.h"
#include "inc.h"
#include "external.h"
#include "batch.h"

#ifdef WEBAPI

#ifdef __CYGWIN32__
#include <windows.h>
#include "gui/resource.h"

#define WM_WEBAPINOTIFY		WM_USER+1
#define WM_WEBAPI_EXIT		WM_USER+2
#define WM_WEBAPI_SHOWERROR	WM_USER+3

static NOTIFYICONDATA TrayIcon;


typedef struct {
	int argc;
	char **argv;
} main_args;
DWORD WINAPI thread_main(LPVOID lpParameter);
#endif

#include "webapi.h"
#endif



#if CPU_DETECT
extern int CPU_detect(void);
#endif

extern struct fmt_main fmt_DES, fmt_BSDI, fmt_MD5, fmt_BF;
extern struct fmt_main fmt_AFS, fmt_LM, fmt_NT, fmt_PO, fmt_rawMD5go;
extern struct fmt_main fmt_hmacMD5;
extern struct fmt_main fmt_MYSQL_fast;
extern struct fmt_main fmt_MYSQL;
extern struct fmt_main fmt_IPB2;
extern struct fmt_main fmt_MD5_apache;
extern struct fmt_main fmt_BFEgg;
extern struct fmt_main fmt_KRB5;
extern struct fmt_main fmt_oracle;
extern struct fmt_main fmt_mysqlSHA1;
extern struct fmt_main fmt_NSLDAP;
extern struct fmt_main fmt_NSLDAPS;
extern struct fmt_main fmt_rawSHA1;
extern struct fmt_main fmt_saltSHA1;
extern struct fmt_main fmt_lotus5;
extern struct fmt_main fmt_DOMINOSEC;
extern struct fmt_main fmt_NETLM;
extern struct fmt_main fmt_NETNTLM;
extern struct fmt_main fmt_NETLMv2;
extern struct fmt_main fmt_NETHALFLM;
extern struct fmt_main fmt_mscash;
extern struct fmt_main fmt_mssql;
extern struct fmt_main fmt_mssql05;
extern struct fmt_main fmt_EPI;
extern struct fmt_main fmt_PHPS;

extern int unshadow(int argc, char **argv);
extern int unafs(int argc, char **argv);
extern int undrop(int argc, char **argv);
extern int unique(int argc, char **argv);

static struct db_main database;
static struct fmt_main dummy_format;

static void john_register_one(struct fmt_main *format)
{
    if (options.format)
	if (strcmp(options.format, format->params.label)) return;

	fmt_register(format);
}

static void john_register_all(void)
{
	if (options.format) strlwr(options.format);

	john_register_one(&fmt_DES);
	john_register_one(&fmt_MD5);
	john_register_one(&fmt_rawMD5go);
	john_register_one(&fmt_MYSQL_fast);
	john_register_one(&fmt_rawSHA1);
	john_register_one(&fmt_mysqlSHA1);
	john_register_one(&fmt_BF);
	john_register_one(&fmt_BFEgg);
	john_register_one(&fmt_LM);
	john_register_one(&fmt_NT);
	john_register_one(&fmt_BSDI);
	john_register_one(&fmt_MD5_apache);
	john_register_one(&fmt_hmacMD5);
	john_register_one(&fmt_PO);
        john_register_one(&fmt_IPB2);
	john_register_one(&fmt_saltSHA1);
	john_register_one(&fmt_KRB5);
	john_register_one(&fmt_NSLDAP);
	john_register_one(&fmt_NSLDAPS);
	john_register_one(&fmt_AFS);
	john_register_one(&fmt_MYSQL);
	john_register_one(&fmt_lotus5);
	john_register_one(&fmt_DOMINOSEC);
	john_register_one(&fmt_NETLM);
	john_register_one(&fmt_NETNTLM);
	john_register_one(&fmt_NETLMv2);
	john_register_one(&fmt_NETHALFLM);
	john_register_one(&fmt_mssql);
	john_register_one(&fmt_mssql05);
	john_register_one(&fmt_EPI);
	john_register_one(&fmt_PHPS);
	john_register_one(&fmt_oracle);
	john_register_one(&fmt_mscash);

	if (!fmt_list) {
		fprintf(stderr, "Unknown ciphertext format name requested\n");
		error();
	}
}

static void john_log_format(void)
{
	int min_chunk, chunk;

	log_event("- Hash type: %.100s (lengths up to %d%s)",
		database.format->params.format_name,
		database.format->params.plaintext_length,
		database.format->methods.split != fmt_default_split ?
		", longer passwords split" : "");

	log_event("- Algorithm: %.100s",
		database.format->params.algorithm_name);

	chunk = min_chunk = database.format->params.max_keys_per_crypt;
	if (options.flags & (FLG_SINGLE_CHK | FLG_BATCH_CHK) &&
	    chunk < SINGLE_HASH_MIN)
			chunk = SINGLE_HASH_MIN;
	if (chunk > 1)
		log_event("- Candidate passwords %s be buffered and "
			"tried in chunks of %d",
			min_chunk > 1 ? "will" : "may",
			chunk);
}

static char *john_loaded_counts(void)
{
	static char s_loaded_counts[80];

	if (database.password_count == 1)
		return "1 password hash";

	sprintf(s_loaded_counts,
		database.salt_count > 1 ?
		"%d password hashes with %d different salts" :
		"%d password hashes with no different salts",
		database.password_count,
		database.salt_count);

	return s_loaded_counts;
}

static void john_load(void)
{
	struct list_entry *current;

	umask(077);

	if (options.flags & FLG_EXTERNAL_CHK)
		ext_init(options.external);

	if (options.flags & FLG_MAKECHR_CHK) {
		options.loader.flags |= DB_CRACKED;
		ldr_init_database(&database, &options.loader);

		if (options.flags & FLG_PASSWD) {
			ldr_show_pot_file(&database, POT_NAME);

			database.options->flags |= DB_PLAINTEXTS;
			if ((current = options.passwd->head))
			do {
				ldr_show_pw_file(&database, current->data);
			} while ((current = current->next));
		} else {
			database.options->flags |= DB_PLAINTEXTS;
			ldr_show_pot_file(&database, POT_NAME);
		}

		return;
	}

	if (options.flags & FLG_STDOUT) {
		ldr_init_database(&database, &options.loader);
		database.format = &dummy_format;
		memset(&dummy_format, 0, sizeof(dummy_format));
		dummy_format.params.plaintext_length = options.length;
		dummy_format.params.flags = FMT_CASE | FMT_8_BIT;
	}

	if (options.flags & FLG_PASSWD) {
		if (options.flags & FLG_SHOW_CHK) {
			options.loader.flags |= DB_CRACKED;
			ldr_init_database(&database, &options.loader);

			ldr_show_pot_file(&database, POT_NAME);

			if ((current = options.passwd->head))
			do {
				ldr_show_pw_file(&database, current->data);
			} while ((current = current->next));

			printf("%s%d password hash%s cracked, %d left\n",
				database.guess_count ? "\n" : "",
				database.guess_count,
				database.guess_count != 1 ? "es" : "",
				database.password_count -
				database.guess_count);

			return;
		}

		if (options.flags & (FLG_SINGLE_CHK | FLG_BATCH_CHK))
			options.loader.flags |= DB_WORDS;
		else
		if (mem_saving_level)
			options.loader.flags &= ~DB_LOGIN;
		ldr_init_database(&database, &options.loader);

		if ((current = options.passwd->head))
		do {
			ldr_load_pw_file(&database, current->data);
		} while ((current = current->next));

		if ((options.flags & FLG_CRACKING_CHK) &&
		    database.password_count) {
			log_init(LOG_NAME, NULL, options.session);
			if (status_restored_time)
				log_event("Continuing an interrupted session");
			else
				log_event("Starting a new session");
			log_event("Loaded a total of %s", john_loaded_counts());
		}

		ldr_load_pot_file(&database, POT_NAME);

		ldr_fix_database(&database);

		if (database.password_count) {
			log_event("Remaining %s", john_loaded_counts());
			printf("Loaded %s (%s [%s])\n",
				john_loaded_counts(),
				database.format->params.format_name,
				database.format->params.algorithm_name);
		} else {
			log_discard();
			puts("No password hashes loaded");
		}

		if ((options.flags & FLG_PWD_REQ) && !database.salts) exit(0);
	}
}

static void john_init(char *name, int argc, char **argv)
{
#if CPU_DETECT
	int detected;

	switch ((detected = CPU_detect())) {
#if CPU_REQ
	case 0:
#if CPU_FALLBACK
#if defined(__DJGPP__) || defined(__CYGWIN32__)
#error CPU_FALLBACK is incompatible with the current DOS and Win32 code
#endif
	case 2:
		execv(JOHN_SYSTEMWIDE_EXEC "/" CPU_FALLBACK_BINARY, argv);
		perror("execv: " JOHN_SYSTEMWIDE_EXEC "/" CPU_FALLBACK_BINARY);
#endif
		if (!detected)
			fprintf(stderr, "Sorry, %s is required\n", CPU_NAME);
		error();
#endif
	default:
		break;
	}
#endif

	path_init(argv);

#if JOHN_SYSTEMWIDE
	cfg_init(CFG_PRIVATE_FULL_NAME, 1);
	cfg_init(CFG_PRIVATE_ALT_NAME, 1);
#endif
	cfg_init(CFG_FULL_NAME, 1);
	cfg_init(CFG_ALT_NAME, 0);

	status_init(NULL, 1);
	opt_init(name, argc, argv);

	john_register_all();

	common_init();

	sig_init();


#ifdef WEBAPI
	/*
	 * Initialize curl, register node if needed, else login
	 *
	 */
	if(webapi_init())
		error();
		
	if(options.webapi_register) {
		char *username = options.webapi_register;
		char *password = NULL;
		char ciphers[1024] = { 0 };
		struct fmt_main *format = fmt_list;

		if(*options.webapi_register == '\0'
			|| (password = strchr(options.webapi_register, ':')) == NULL) {
			fprintf(stderr, "You need to specify the account in the format:  username:password\n");
			error();
		}

		*password = 0;
		password++;

		do {
			strcat(ciphers, format->params.label);
			strcat(ciphers, ",");
		} while((format = format->next) != NULL);
		
		if(*ciphers) 
			ciphers[strlen(ciphers) - 1] = '\0';
		

		fprintf(stderr, "webapi: Trying to register node..\n");
		if(webapi_register(username, password, ciphers)) {

#ifdef __CYGWIN32__
			webapi_registry_delete("username");
			webapi_registry_delete("password");
			MessageBox(0, "Registration failed, likely due to an invalid username or password\n"
					"Restart the program and try again.",
					"DistributedCracking.net client", MB_OK);
#endif

			error();
		}
	}
	else if((options.flags & FLG_NET_CHK) == FLG_NET_CHK)
		if(webapi_login()) {
#ifdef __CYGWIN32__
			// We better let the user know about it
			MessageBox(0, "Node authentication failed for an unknown reason. We will now terminate.\n"
					"If this problem persists, please delete HKCU\\Software\\DistributedCracking.net\\Authcookie",
					"DistributedCracking.net client", MB_OK);
#endif
			error();
		}
#endif

	john_load();

}

static void john_run(void)
{
	if (options.flags & FLG_TEST_CHK)
		benchmark_all();
	else
	if (options.flags & FLG_MAKECHR_CHK)
		do_makechars(&database, options.charset);
	else
	if (options.flags & FLG_CRACKING_CHK) {
		if (!(options.flags & FLG_STDOUT)) {
			status_init(NULL, 1);
			log_init(LOG_NAME, POT_NAME, options.session);
			john_log_format();
			if (cfg_get_bool(SECTION_OPTIONS, NULL, "Idle"))
				log_event("- Configured to use otherwise idle "
					"processor cycles only");
		}
		tty_init();

		if (options.flags & FLG_SINGLE_CHK)
			do_single_crack(&database);
		else
		if (options.flags & FLG_WORDLIST_CHK)
			do_wordlist_crack(&database, options.wordlist,
				(options.flags & FLG_RULES) != 0);
		else
		if (options.flags & FLG_INC_CHK)
			do_incremental_crack(&database, options.charset);
		else
		if (options.flags & FLG_EXTERNAL_CHK)
			do_external_crack(&database);
		else
		if (options.flags & FLG_BATCH_CHK)
			do_batch_crack(&database);

		status_print();
		tty_done();
	}

	/*
	 * This is the main DistributedCracking.net loop
	 *
	 */
	else if((options.flags & FLG_NET_CHK) != 0) {
		int ret;
		char attack_mode[16];
		char attack_options[16];
		char wordlist_file[PATH_MAX];
		
		for(;;) {
			sprintf(job_name, "<Retrieving work>");
			ret = webapi_fetch_work(&database, attack_mode, attack_options);
			check_abort(0);
			if(ret < 0) {
				printf("[webapi] Error fetching work, return value was %d\n", ret);
				sleep(1);
				continue;
			}
			
			attack_mode[sizeof(attack_mode) - 1] = 0;
			attack_options[sizeof(attack_options) - 1] = 0;


			ret = webapi_fetch_state();
			check_abort(0);
			if(ret != 0) {
				// Start over, no available packets (ret == 1)
				// or an error occured (ret == -1)
				sleep(1);
				continue;
			}

			status_init(NULL, 1);
			log_init(LOG_NAME, POT_NAME, options.session);
			john_log_format();
			tty_init();


			if(!strcmp(attack_mode, "incremental")) {
				do_incremental_crack(&database, attack_options);
			}
			else if(!strcmp(attack_mode, "wordlist")) {
				do_wordlist_crack(&database, wordlist_file, strcmp(attack_options, "quick") == 0? 0: 1);
			}
			
			if(inc_rec_state.words_generated == inc_rec_state.words_requested) {
				webapi_packet_done();
				status_print();
			}
			else {
				printf("[webapi] Packet NOT finished!\n");
				fflush(stdout);
			}

			tty_done();
			check_abort(0);
		}
	}
}


static void john_done(void)
{
	path_done();

	if ((options.flags & FLG_CRACKING_CHK) &&
	    !(options.flags & FLG_STDOUT)) {
		if (event_abort)
			log_event("Session aborted");
		else
			log_event("Session completed");
	}
	log_done();
	check_abort(0);
}



#if defined(WEBAPI) && defined(__CYGWIN32__)
/*
 * The node registration dialog dispatcher routine
 *
 */
static BOOL CALLBACK webapi_register_proc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	char username[100];
	char password[100];

	switch(uMsg) {
		case WM_INITDIALOG:
			return TRUE;
			
		case WM_CLOSE:
			EndDialog(hWnd, 1);
			break;
			
		case WM_COMMAND:
			if(LOWORD(wParam) != IDC_REGISTER)
				break;
				
			GetDlgItemText(hWnd, IDC_USERNAME, username, sizeof(username) - 1);
			webapi_registry_set("username", username);

			GetDlgItemText(hWnd, IDC_PASSWORD, password, sizeof(password) - 1);
			webapi_registry_set("password", password);
			EndDialog(hWnd, 0);
			break;
			
		default:
			break;
	}
	
	return FALSE;
}


/*
 * The main window's message dispatcher
 * Mainly used for dealing with the system tray icon
 *
 */
static LRESULT CALLBACK webapi_window_proc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	HMENU hPopup;
	POINT pos;

	switch (uMsg) {
		case WM_WEBAPINOTIFY:
			if(lParam == WM_RBUTTONUP) {
				int ret;
				char buf[1024];
				
				GetCursorPos(&pos);
				SetForegroundWindow(hWnd);
				
				hPopup = CreatePopupMenu();
				AppendMenu(hPopup, MF_STRING | MF_GRAYED, 0, "DistributedCracking.net " WEBAPI_VERSION);
				AppendMenu(hPopup, MF_SEPARATOR, 0, "---");
				
				AppendMenu(hPopup, MF_STRING | MF_GRAYED, 0, "Current job:");
				sprintf(buf, "  %s (%.2f%%)", job_name, inc_rec_state.words_requested? (double)100.0 * inc_rec_state.words_generated / (double)inc_rec_state.words_requested: 0.0);
				AppendMenu(hPopup, MF_STRING | MF_GRAYED, 0, buf);
				AppendMenu(hPopup, MF_SEPARATOR, 0, "---");

				if(webapi_last_error_msg && *webapi_last_error_msg) {
					AppendMenu(hPopup, MF_STRING , WM_WEBAPI_SHOWERROR, "Show last error message");
					AppendMenu(hPopup, MF_SEPARATOR, 0, "---");
				}
				

				if (cfg_get_bool(SECTION_OPTIONS, NULL, "Idle")) {
					sprintf(buf, "Run when idle only: YES");
					AppendMenu(hPopup, MF_STRING | MF_GRAYED | MF_CHECKED, 0, buf);
					sprintf(buf, "  This can be changed in john.conf");
					AppendMenu(hPopup, MF_STRING | MF_GRAYED, 0, buf);
					AppendMenu(hPopup, MF_SEPARATOR, 0, "---");
				}

				AppendMenu(hPopup, MF_STRING, WM_WEBAPI_EXIT, "Exit");

				ret = TrackPopupMenuEx(hPopup,
					TPM_RETURNCMD | TPM_RIGHTBUTTON,
					pos.x, pos.y,
					hWnd, NULL); 
				DestroyMenu(hPopup);
				
				PostMessage(hWnd, 0, 0, 0);
				if(ret == WM_WEBAPI_EXIT) {
					Shell_NotifyIcon(NIM_DELETE,&TrayIcon);
					PostQuitMessage(0);
				}
				else if(ret == WM_WEBAPI_SHOWERROR) 
					MessageBox(0, webapi_last_error_msg, "DistributedCracking.net: Showing last error message", MB_OK);

			}
			break;


		case WM_COMMAND:
			if(LOWORD(wParam) == WM_WEBAPI_EXIT) {
				PostMessage(hWnd, WM_DESTROY, 0, 0);
				DestroyWindow(hWnd);
			}
			break;
	

		case WM_DESTROY:
			Shell_NotifyIcon(NIM_DELETE,&TrayIcon);
			PostQuitMessage(0);
			break;

	
		default:
			return DefWindowProc(hWnd, uMsg, wParam, lParam);
			break;

	}			
	
	return 0;
}



/*
 * This is the GUI entry point
 * It will eventually create a thread to run John The Ripper
 * if there's a node auth cookie or username/password are provided
 * for registering
 * 
 */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
	char webapi_window_class[] = "distributedcracking.net";
	HWND hWnd;      
	MSG messages;
	WNDCLASSEX wincl;
	HICON TrayIconImage;
	HANDLE jtrThread;
	DWORD jtrThreadId;

	main_args thread_args;
	int argc = 1;
	char **argv;
	int pos = 0, i, j;



	// The icon shown in the system tray
	// Load it from the .exe's resources
	TrayIconImage = LoadImage(hInstance, MAKEINTRESOURCE(IDI_WEBAPI), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);


	wincl.hInstance = hInstance;
	wincl.lpszClassName = webapi_window_class;
	wincl.lpfnWndProc = webapi_window_proc;
	wincl.style = CS_DBLCLKS;      
	wincl.cbSize = sizeof (WNDCLASSEX);
		
	wincl.hIcon = TrayIconImage;
	wincl.hIconSm = NULL;
	wincl.hCursor = LoadCursor (NULL, IDC_ARROW);
	wincl.lpszMenuName = NULL;
	wincl.cbClsExtra = 0;
	wincl.cbWndExtra = 0;
	wincl.hbrBackground = (HBRUSH) COLOR_BACKGROUND;
	if(!RegisterClassEx(&wincl))
		return 0;


	// Hidden window for tray callback
	// XXX - Is this really needed?!
	hWnd = CreateWindowEx(0,
		webapi_window_class,
		webapi_window_class,
		0,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		400,
		430,
		HWND_DESKTOP,
		NULL,
		hInstance,NULL);

	while(webapi_registry_get(WEBAPI_REG_KEYNAME) == NULL
		&& (webapi_registry_get("username") == NULL && webapi_registry_get("password") == NULL)) {

		// Exit if someone hits the X		
		if(DialogBox(hInstance, MAKEINTRESOURCE(IDD_FORMVIEW), hWnd, webapi_register_proc))
			exit(-1);
	}


	// Initialize datastructure for the tray icon
	TrayIcon.cbSize = sizeof(NOTIFYICONDATA);
	TrayIcon.hWnd = hWnd;
	TrayIcon.uID = 0;
	TrayIcon.hIcon = TrayIconImage;
	TrayIcon.uCallbackMessage = WM_WEBAPINOTIFY;
	TrayIcon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
	strcpy(TrayIcon.szTip, "DistributedCracking.NET client");
	Shell_NotifyIcon(NIM_ADD, &TrayIcon);



	// Yuck. GUI apps surely aren't meant to deal with command line options
	for (i = 0; i < strlen(lpCmdLine); i++){ 
		if (lpCmdLine[i] == '"') { 
			i++; 
			while (lpCmdLine[i] != '"' && i < strlen(lpCmdLine)) { 
				i++; 
			} 
			argc++; 
		}
		else { 
			while (lpCmdLine[i] != ' ' && i < strlen(lpCmdLine)) { 
				i++; 
			} 
			argc++; 
		} 
	} 

	// alloc one extra to give room for --register/--net argument
	argv = (char**)malloc(sizeof(char*)* (argc+1 + 1)); 

	argv[0] = (char*)malloc(1024); 
	GetModuleFileName(0, argv[0],1024); 

	for(j=1; j<argc; j++){ 
		argv[j] = (char*)malloc(strlen(lpCmdLine)+10); 
	} 


	argv[argc] = 0; 



	argc = 1; 
	pos = 0; 
	for (i = 0; i < strlen(lpCmdLine); i++){ 
		if(i == 0) {
			while(lpCmdLine[i] && lpCmdLine[i] != ' ')
				i++;
			if(lpCmdLine[i] == ' ')
				i++;
		}

		if (lpCmdLine[i] == '"'){ 
			i++; 
			while (lpCmdLine[i] != '"' && i < strlen(lpCmdLine)) { 
				argv[argc][pos] = lpCmdLine[i]; 
				i++; 
				pos++; 
			} 
			argv[argc][pos] = '\0'; 
			argc++; 
			pos = 0; 
		}
		else if(lpCmdLine[i]) { 
			while (lpCmdLine[i] != ' ' && i < strlen(lpCmdLine)) { 
				argv[argc][pos] = lpCmdLine[i]; 
				i++; 
				pos++; 
			} 
			argv[argc][pos] = '\0'; 
			argc++; 
			pos = 0; 
		} 
	} 


	// Add --register argument if there's no node authcookie
	if(webapi_registry_get(WEBAPI_REG_KEYNAME) == NULL) {
		char buf[1024];
		sprintf(buf, "--register=%s", webapi_registry_get("username"));
		sprintf(buf + strlen(buf), ":%s", webapi_registry_get("password"));
		argv[argc++] = strdup(buf);
	}
	else
		argv[argc++] = strdup("--net");

	argv[argc] = 0; 


	// Create the "UNIX" thread for John The Ripper
	thread_args.argc = argc;
	thread_args.argv = argv;
	jtrThread = CreateThread(NULL, 0, thread_main, (LPVOID)&thread_args, 0, &jtrThreadId);



	// Take care of GUI stuff
	while(GetMessage(&messages, NULL, 0, 0)) {
		TranslateMessage(&messages);
  		DispatchMessage(&messages);
	}


	for(i=0;i<argc;i++)
		free(argv[i]);
	free(argv);

	 return messages.wParam;
}


/*
 * In Windows the main() routine is actually run in 
 * a seperate thread
 *
 */
DWORD WINAPI thread_main(LPVOID lpParameter) {
	int argc = ((main_args *)lpParameter)->argc;
	char **argv = ((main_args *)lpParameter)->argv;
#else
int main(int argc, char **argv) {
#endif
	char *name;

#ifdef __DJGPP__
	if (--argc <= 0) return 1;
	if ((name = strrchr(argv[0], '/')))
		strcpy(name + 1, argv[1]);
	name = argv[1];
	argv[1] = argv[0];
	argv++;
#else
	if (!argv[0])
		name = "john";
	else
	if ((name = strrchr(argv[0], '/')))
		name++;
	else
		name = argv[0];
#endif

#ifdef __CYGWIN32__
	// GUI apps have no console attached so redirect to /dev/null
	freopen("/dev/null", "r", stdin);
	if(webapi_registry_get("debug") == NULL) {
		freopen("/dev/null", "w", stderr);
		freopen("/dev/null", "w", stdout);
	}
	else {
		freopen("log.stderr.txt", "w", stderr);
		freopen("log.stdout.txt", "w", stdout);
	}


	strlwr(name);
	if (strlen(name) > 4 && !strcmp(name + strlen(name) - 4, ".exe"))
		name[strlen(name) - 4] = 0;
#endif

	if (!strcmp(name, "unshadow"))
		return unshadow(argc, argv);

	if (!strcmp(name, "unafs"))
		return unafs(argc, argv);

	if (!strcmp(name, "unique"))
		return unique(argc, argv);

	if (!strcmp(name, "undrop"))
               return undrop(argc, argv);
 
	john_init(name, argc, argv);
	john_run();
	john_done();

	return 0;
}
