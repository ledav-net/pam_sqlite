/*
 * PAM authentication module for SQLite
 *
 * SQLite port: Edin Kadribasic <edink@php.net>
 * Extended SQL configuration support by Wez Furlong <wez@thebrainroom.com>
 * Sessions handling by David De Grave <david@ledav.net>
 *
 * Based in part on pam_pgsql.c by David D.W. Downey ("pgpkeys") <david-downey@codecastle.com>
 * 
 * Based in part on pam_unix.c of FreeBSD.
 *
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <time.h>
#include <sqlite3.h>
#if HAVE_CRYPT_H
#include <crypt.h>
#endif

#if HAVE_MHASH_H
#include <mhash.h>
#endif

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION
#include <security/pam_modules.h>
#include "pam_mod_misc.h"

#define PASSWORD_PROMPT		"Password: "
#define PASSWORD_PROMPT_NEW	"New password: "
#define PASSWORD_PROMPT_CONFIRM "Confirm new password: "
#define CONF			"/etc/pam_sqlite.conf"

#define DBGLOG(x...)	if( options->debug ) openlog("PAM_sqlite", LOG_PID, LOG_AUTHPRIV), syslog(LOG_DEBUG, ##x), closelog()
#define INFLOG(x...)	if( options->info  ) openlog("PAM_sqlite", LOG_PID, LOG_AUTHPRIV), syslog(LOG_INFO,  ##x), closelog()
#define SYSLOG(l, x...) openlog("PAM_sqlite", LOG_PID, LOG_AUTHPRIV), syslog(l, ##x), closelog()

typedef enum {
	PW_CLEAR = 1,
#if HAVE_MD5_CRYPT
	PW_CRYPT_MD5,
#endif
#if	HAVE_MHASH_H 
	PW_MD5,
#endif
	PW_CRYPT,
} pw_scheme;

struct module_options {
	char		*database;
	char		*table;
	char		*user_column;
	char		*pwd_column;
	char		*expired_column;
	char		*newtok_column;
	pw_scheme	pw_type;
	int		debug;
	int		info;
	char		*sql_verify;
	char		*sql_check_expired;
	char		*sql_check_newtok;
	char		*sql_set_passwd;
	char		*sql_open_session;
	char		*sql_close_session;
};

#define GROW(x)	\
if (x > buflen - dest - 1) {				   \
	char *grow;                                        \
	buflen += 256 + x;                                 \
	grow = realloc(buf, buflen + 256 + x);             \
	if (grow == NULL) { free(buf); return NULL; }      \
	buf = grow;                                        \
}

#define APPEND(str, len)	GROW(len); memcpy(buf + dest, str, len); dest += len
#define APPENDS(str)		len = strlen(str); APPEND(str, len)

static char *format_query(const char *template, struct module_options *options,
	const char *user, const char *passwd)
{
	char *buf = malloc(256);
	int buflen = 256;
	int dest = 0, len;
	const char *src = template;
	char *pct;
	char *tmp;

	while (*src) {
		pct = strchr(src, '%');

		if (pct) {
			/* copy from current position to % char into buffer */
			if (pct != src) {
				len = pct - src;
				APPEND(src, len);
			}
			
			/* decode the escape */
			switch(pct[1]) {
				case 'U':	/* username */
					if (user) {
						tmp = sqlite3_mprintf("%q", user);
						len = strlen(tmp);
						APPEND(tmp, len);
						sqlite3_free(tmp);
					}
					break;
				case 'P':	/* password */
					if (passwd) {
						tmp = sqlite3_mprintf("%q", passwd);
						len = strlen(tmp);
						APPEND(tmp, len);
						sqlite3_free(tmp);
					}
					break;

				case 'O':	/* option value */
					pct++;
					switch (pct[1]) {
						case 'p':	/* passwd */
							APPENDS(options->pwd_column);
							break;
						case 'u':	/* username */
							APPENDS(options->user_column);
							break;
						case 't':	/* table */
							APPENDS(options->table);
							break;
						case 'x':	/* expired */
							APPENDS(options->expired_column);
							break;
						case 'n':	/* newtok */
							APPENDS(options->newtok_column);
							break;
					}
					break;
					
				case '%':	/* quoted % sign */
					APPEND(pct, 1);
					break;
					
				default:	/* unknown */
					APPEND(pct, 2);
					break;
			}
			src = pct + 2;
		} else {
			/* copy rest of string into buffer and we're done */
			len = strlen(src);
			APPEND(src, len);
			break;
		}
	}

	buf[dest] = '\0';
	return buf;
}

static void
get_module_options_from_file(const char *filename, struct module_options *opts, int warn);

/* private: parse and set the specified string option */
static void
set_module_option(const char *option, struct module_options *options)
{
	char *buf, *eq;
	char *val, *end;

	if(!option || !*option)
		return;

	buf = strdup(option);

	if((eq = strchr(buf, '='))) {
		end = eq - 1;
		val = eq + 1;
		if(end <= buf || !*val)
			return;
		while(end > buf && isspace(*end))
			end--;
		end++;
		*end = '\0';
		while(*val && isspace(*val))
			val++;
	} else {
		val = NULL;
	}

	DBGLOG("setting option: %s=>%s\n", buf, val);

	if(!strcmp(buf, "database")) {
		options->database = strdup(val);
	} else if(!strcmp(buf, "table")) {
		options->table = strdup(val);
	} else if(!strcmp(buf, "user_column")) {
		options->user_column = strdup(val);
	} else if(!strcmp(buf, "pwd_column")) {
		options->pwd_column = strdup(val);
	} else if(!strcmp(buf, "expired_column")) {
		options->expired_column = strdup(val);
	} else if(!strcmp(buf, "newtok_column")) {
		options->newtok_column = strdup(val);
	} else if(!strcmp(buf, "pw_type")) {
		options->pw_type = PW_CLEAR;
		if(!strcmp(val, "crypt")) {
			options->pw_type = PW_CRYPT;
		}
#if HAVE_MHASH_H
		else if(!strcmp(val, "md5")) {
			options->pw_type = PW_MD5;
		}
#endif
#if HAVE_MD5_CRYPT
		else if(!strcmp(val, "crypt_md5")) {
			options->pw_type = PW_CRYPT_MD5;
		}
#endif
	} else if(!strcmp(buf, "debug")) {
		options->debug = 1;
        } else if(!strcmp(buf, "info")) {
                options->info = 1;
	} else if (!strcmp(buf, "config_file")) {
		get_module_options_from_file(val, options, 1);
	} else if (!strcmp(buf, "sql_verify")) {
		options->sql_verify = strdup(val);
	} else if (!strcmp(buf, "sql_check_expired")) {
		options->sql_check_expired = strdup(val);
	} else if (!strcmp(buf, "sql_check_newtok")) {
		options->sql_check_newtok = strdup(val);
	} else if (!strcmp(buf, "sql_set_passwd")) {
		options->sql_set_passwd = strdup(val);
	} else if (!strcmp(buf, "sql_open_session")) {
	        options->sql_open_session = strdup(val);
        } else if (!strcmp(buf, "sql_close_session")) {
                options->sql_close_session = strdup(val);
        }

	free(buf);
}

/* private: read module options from a config file */
static void
get_module_options_from_file(const char *filename, struct module_options *opts, int warn)
{
	FILE *fp;

	if ((fp = fopen(filename, "r"))) {
		char line[1024];
		char *str, *end;

		while(fgets(line, sizeof(line), fp)) {
			str = line;
			end = line + strlen(line) - 1;
			while(*str && isspace(*str)) str++;
			while(end > str && isspace(*end)) end--;
			end++;
			*end = '\0';
			if ( *str == '#' || ! *str ) continue;
			set_module_option(str, opts);
		}
		fclose(fp);
	} else if (warn) {
		SYSLOG(LOG_WARNING, "unable to read config file %s", filename);
	}
}

/* private: read module options from file or commandline */
static int 
get_module_options(int argc, const char **argv, struct module_options **options)
{
	int i, rc;
	struct module_options *opts;

	opts = (struct module_options *)malloc(sizeof(*opts));
	bzero(opts, sizeof(*opts));
	opts->pw_type = PW_CLEAR;
	rc = 0;

	get_module_options_from_file(CONF, opts, 0);

	for(i = 0; i < argc; i++) {
		if(pam_std_option(&rc, argv[i]) == 0)
			continue;
		set_module_option(argv[i], opts);
	}
	*options = opts;

	return rc;
}

/* private: free module options returned by get_module_options() */
static void
free_module_options(struct module_options *options)
{
	free(options->database);
	free(options->table);
	free(options->user_column);
	free(options->pwd_column);
	free(options->expired_column);
	free(options->newtok_column);
	free(options->sql_verify);
	free(options->sql_check_expired);
	free(options->sql_check_newtok);
	free(options->sql_set_passwd);
	free(options->sql_open_session);
	free(options->sql_close_session);
	bzero(options, sizeof(*options));
	free(options);
}

/* private: make sure required options are present (in cmdline or conf file) */
static int
options_valid(struct module_options *options)
{
	if(options->database == 0 || options->table == 0 || options->user_column == 0) {
		SYSLOG(LOG_CRIT, "the database, table and user_column options are required.");
		return -1;
	}
	return 0;
}

/* private: open SQLite database */
static sqlite3 *pam_sqlite_connect(struct module_options *options)
{
  sqlite3 *sdb = NULL;

  if ( sqlite3_open(options->database, &sdb) != SQLITE_OK ) {
    SYSLOG(LOG_ERR, "Error opening SQLite database (%s)", sqlite3_errmsg(sdb));
  }

  if ( sqlite3_busy_timeout(sdb, 30000) != SQLITE_OK ) {
    SYSLOG(LOG_WARNING, "sqlite3_busy_timeout() error !");
  }

  return sdb;
}

/* private: generate random salt character */
static char *
crypt_make_salt(struct module_options *options)
{
#if HAVE_MD5_CRYPT
	int i;	
#endif
	time_t now;
	static unsigned long x;
	static char result[13];
	static char salt_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

	time(&now);
	x += now + getpid() + clock();
	srandom(x);

	switch(options->pw_type) {
        	case PW_CRYPT:
	        	result[0] = salt_chars[random() % 64];
	        	result[1] = salt_chars[random() % 64];
	        	result[2] = '\0';
                break;
#if HAVE_MD5_CRYPT
                case PW_CRYPT_MD5:
		        result[0]='$';
		        result[1]='1';
		        result[2]='$';
		        for (i=3; i<11; i++) {
                                result[i] = salt_chars[random() % 64];
                        }
                        result[11] = '$';
                        result[12]='\0';
                break;
#endif
                default:
                        result[0] = '\0';
	}
	return result;
}

/* private: encrypt password using the preferred encryption scheme */
static char *
encrypt_password(struct module_options *options, const char *pass,const char *salt)
{
	char *s = NULL;

	switch(options->pw_type) {

#if HAVE_MD5_CRYPT
    	        case PW_CRYPT_MD5:
    	                if (salt==NULL) {
                                s = strdup(crypt(pass, crypt_make_salt(options)));
                        } else {
                	        s = strdup(crypt(pass, salt));
                        }
                break;
#endif

#if HAVE_MHASH_H
                case PW_MD5:{
		        char		*buf;
                        int		buf_size;
                        MHASH		handle;
                        unsigned char	*hash;
                        
                        handle = mhash_init(MHASH_MD5);

                        if(handle == MHASH_FAILED) {
	    	                SYSLOG(LOG_ERR, "could not initialize mhash library!");
                        } else {
        	                unsigned int i;

                                mhash(handle, pass, strlen(pass));
                                hash = mhash_end(handle);
                                
                                if (hash != NULL) {
                                        buf_size = (mhash_get_block_size(MHASH_MD5) * 2)+1;
                                        buf = (char *)malloc(buf_size);
                                        bzero(buf, buf_size);
                                        for(i = 0; i < mhash_get_block_size(MHASH_MD5); i++) {
	        		                sprintf(&buf[i * 2], "%.2x", hash[i]);
                                        }
                                        free(hash);
                                        s = buf;
                                } else {
                                        s = strdup("!");
                                }
                        }
                }
                break;
#endif
                case PW_CRYPT:
                        s = strdup(crypt(pass, crypt_make_salt(options)));
                break;
	
                case PW_CLEAR:
                default:
                        s = strdup(pass);
        }
	return s;
}

/* private: authenticate user and passwd against database */
static int
auth_verify_password(const char *user, const char *passwd, 
					 struct module_options *options)
{
	int res;
	sqlite3 *conn;
	sqlite3_stmt *stmt = NULL;
	int rc;
	const char *tail;
	char *query;

#define CRYPT_LEN 13

	if(!(conn = pam_sqlite_connect(options)))
		return PAM_AUTH_ERR;

	query = format_query(options->sql_verify
                              ? options->sql_verify
                              : "SELECT %Op FROM %Ot WHERE %Ou='%U'",
                             options, user, passwd);

	DBGLOG("query: %s", query);
	
	res = sqlite3_prepare(conn, query, -1, &stmt, &tail);
   
	free(query);

	if (res != SQLITE_OK) {
		SYSLOG(LOG_ERR, "Error executing SQLite query (%s)", sqlite3_errmsg(conn));
		return PAM_AUTH_ERR;
	}
	
	rc = PAM_AUTH_ERR;

	if (SQLITE_ROW != sqlite3_step(stmt)) {
		rc = PAM_USER_UNKNOWN;
		DBGLOG("no rows to retrieve");
	} else {
		const char *stored_pw = (char *)sqlite3_column_text(stmt, 0);
		switch(options->pw_type) {
		case PW_CLEAR:
			if(strcmp(passwd, stored_pw) == 0)
				rc = PAM_SUCCESS;
			break;

#if HAVE_MHASH_H
		case PW_MD5:
			if(strcmp(encrypt_password(options, passwd, NULL), stored_pw) == 0)
			        rc = PAM_SUCESS;
                        break;
#endif
#if HAVE_MD5_CRYPT
                case PW_CRYPT_MD5:
                        if(strcmp(crypt(passwd, stored_pw), stored_pw) == 0)
				rc = PAM_SUCCESS;
			break;
#endif

		case PW_CRYPT:
			if(strcmp(crypt(passwd, stored_pw), stored_pw) == 0)
				rc = PAM_SUCCESS;
			break;
		}
	}
	sqlite3_finalize(stmt);
	sqlite3_close(conn);
	return rc;
}

/* public: authenticate user */
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct module_options *options;
	const char *user, *password;
	int rc, std_flags;

	if((rc = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		return rc;

	std_flags = get_module_options(argc, argv, &options);
	if(options_valid(options) != 0) {
		free_module_options(options);
		return PAM_AUTH_ERR;
	}

	DBGLOG("attempting to authenticate: %s", user);

	if((rc = pam_get_pass(pamh, &password, PASSWORD_PROMPT, std_flags) 
		!= PAM_SUCCESS)) {
		free_module_options(options);
		return rc;
	}

	if((rc = auth_verify_password(user, password, options)) != PAM_SUCCESS) {
		free_module_options(options);
		return rc;
	}

	INFLOG("(%s) user %s authenticated.", pam_get_service(pamh), user);
	free_module_options(options);

	return PAM_SUCCESS;
}

/* public: check if account has expired, or needs new password */
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
							const char **argv)
{
	struct module_options *options;
	const char *user;
	int rc;
	sqlite3 *conn;
	sqlite3_stmt *stmt = NULL;
	char *query;
	const char *tail;
	int res;
	
	get_module_options(argc, argv, &options);
	if(options_valid(options) != 0) {
		free_module_options(options);
		return PAM_AUTH_ERR;
	}

	/* both not specified, just succeed. */
	if(options->expired_column == 0 && options->newtok_column == 0) {
		free_module_options(options);
		return PAM_SUCCESS;
	}

	if((rc = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		SYSLOG(LOG_ERR, "could not retrieve user");
		free_module_options(options);
		return rc;
	}

	if(!(conn = pam_sqlite_connect(options))) {
		free_module_options(options);
		return PAM_AUTH_ERR;
	}

	/* if account has expired then expired_column = '1' or 'y' */
	if(options->expired_column || options->sql_check_expired) {
		
		query = format_query(options->sql_check_expired ? options->sql_check_expired :
				"SELECT 1 from %Ot WHERE %Ou='%U' AND (%Ox='y' OR %Ox='1')",
				options, user, NULL);
		
		DBGLOG("query: %s", query);

		res = sqlite3_prepare(conn, query, -1, &stmt, &tail);
   
		free(query);

		if (res != SQLITE_OK) {
			DBGLOG("Error executing SQLite query (%s)", sqlite3_errmsg(conn));
			free_module_options(options);
			sqlite3_close(conn);
			return PAM_AUTH_ERR;
		}

		res = sqlite3_step(stmt);

		if(SQLITE_ROW == res) {
			sqlite3_finalize(stmt);
			sqlite3_close(conn);
			free_module_options(options);
			return PAM_ACCT_EXPIRED;
		}
		sqlite3_finalize(stmt);
	}
	
	/* if new password is required then newtok_column = 'y' or '1' */
	if(options->newtok_column || options->sql_check_newtok) {
		query = format_query(options->sql_check_newtok ? options->sql_check_newtok :
				"SELECT 1 FROM %Ot WHERE %Ou='%U' AND (%On='y' OR %On='1')",
				options, user, NULL);

		DBGLOG("query: %s", query);

		res = sqlite3_prepare(conn, query, -1, &stmt, &tail);	
	
		free(query);

		if (res != SQLITE_OK) {
			DBGLOG("Error executing SQLite query (%s)", sqlite3_errmsg(conn));
			sqlite3_close(conn);
			free_module_options(options);
			return PAM_AUTH_ERR;
		}

		res = sqlite3_step(stmt);

		if(SQLITE_ROW == res) {
			sqlite3_finalize(stmt);
            sqlite3_close(conn);
			free_module_options(options);
			return PAM_NEW_AUTHTOK_REQD;
		}
		sqlite3_finalize(stmt);
	}

	sqlite3_close(conn);
	return PAM_SUCCESS;
}

/* public: change password */
PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct module_options *options;
	int rc, std_flags;
	const char *user, *pass, *newpass;
	char *newpass_crypt;
	sqlite3 *conn;
	char *errtext = NULL;
	char *query;
	int res;
	
	std_flags = get_module_options(argc, argv, &options);
	if(options_valid(options) != 0) {
		free_module_options(options);
		return PAM_AUTH_ERR;
	}
	
	if((rc = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		free_module_options(options);
		return rc;
	}
	
	if(!(conn = pam_sqlite_connect(options))) {
		free_module_options(options);
		return PAM_AUTH_ERR;
	}
	
	if(flags & PAM_PRELIM_CHECK) {
		/* at this point, this is the first time we get called */
		if((rc = pam_get_pass(pamh, &pass, PASSWORD_PROMPT, std_flags)) == PAM_SUCCESS) {
			if((rc = auth_verify_password(user, pass, options)) == PAM_SUCCESS) {
				rc = pam_set_item(pamh, PAM_OLDAUTHTOK, (const void *)pass);
				if(rc != PAM_SUCCESS) {
					SYSLOG(LOG_ERR, "failed to set PAM_OLDAUTHTOK!");
				}
				free_module_options(options);
				return rc;
			} else {
				DBGLOG("password verification failed for '%s'", user);
				return rc;
			}
		} else {
			SYSLOG(LOG_ERR, "could not retrieve password from '%s'", user);
			return PAM_AUTH_ERR;
		}
	} else if(flags & PAM_UPDATE_AUTHTOK) {
		pass = newpass = NULL;
		rc = pam_get_item(pamh, PAM_OLDAUTHTOK, (const void **) &pass);
		if(rc != PAM_SUCCESS) {
			SYSLOG(LOG_ERR, "could not retrieve old token");
			free_module_options(options);
			return rc;
		}
		rc = auth_verify_password(user, pass, options);
		if(rc != PAM_SUCCESS) {
			SYSLOG(LOG_NOTICE, "(%s) user '%s' not authenticated.", pam_get_service(pamh), user);
			free_module_options(options);
			return rc;
		}

		/* get and confirm the new passwords */
		rc = pam_get_confirm_pass(pamh, &newpass, PASSWORD_PROMPT_NEW, PASSWORD_PROMPT_CONFIRM, std_flags);
		if(rc != PAM_SUCCESS) {
			SYSLOG(LOG_ERR, "could not retrieve new authentication tokens");
			free_module_options(options);
			return rc;
		}

		/* save the new password for subsequently stacked modules */
		rc = pam_set_item(pamh, PAM_AUTHTOK, (const void *)newpass);
		if(rc != PAM_SUCCESS) {
			SYSLOG(LOG_ERR, "failed to set PAM_AUTHTOK!");
			free_module_options(options);
			return rc;
		}

		/* update the database */
		if(!(newpass_crypt = encrypt_password(options, newpass, NULL))) {
			free_module_options(options);
			DBGLOG("passwd encrypt failed");
			return PAM_BUF_ERR;
		}
		if(!(conn = pam_sqlite_connect(options))) {
			free_module_options(options);
			return PAM_AUTHINFO_UNAVAIL;
		}

		DBGLOG("creating query");

		query = format_query(options->sql_set_passwd ? options->sql_set_passwd :
				"UPDATE %Ot SET %Op='%P' WHERE %Ou='%U'",
				options, user, newpass_crypt);

		res = sqlite3_exec(conn, query, NULL, NULL, &errtext);
		free(query);

		if (SQLITE_OK != res) {
			DBGLOG("query failed[%d]: %s", res, errtext);
			sqlite3_free(errtext);
			free(newpass_crypt);
			free_module_options(options);
			sqlite3_close(conn);
			return PAM_AUTH_ERR;
		}
	
		/* if we get here, we must have succeeded */
		free(newpass_crypt);
		sqlite3_close(conn);
	}

	free_module_options(options);
	INFLOG("(%s) password for '%s' was changed.", pam_get_service(pamh), user);
	return PAM_SUCCESS;
}

/* public: just succeed. */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

/* public: session handling ... */
PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct		module_options *options;
	int 		rc, res, std_flags;
	const char 	*user;
	sqlite3		*conn;
	char		*query, *errtext = NULL;
	                        
	std_flags = get_module_options(argc, argv, &options);
	if(options_valid(options) != 0) {
		free_module_options(options);
		return PAM_SESSION_ERR;
	}

	if ( ! options->sql_open_session ) {
	        free_module_options(options);
	        return PAM_SUCCESS;
	}
	
	DBGLOG("Opening session ...");	        

	if((rc = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		free_module_options(options);
		return rc;
	}

	if(!(conn = pam_sqlite_connect(options))) {
		free_module_options(options);
		return PAM_SESSION_ERR;
	}

	query = format_query(options->sql_open_session, options, user, NULL);
	DBGLOG("query: %s", query);
	
	res = sqlite3_exec(conn, query, NULL, NULL, &errtext);
	free(query);

	if ( res != SQLITE_OK ) {
	        DBGLOG("query failed[%d]: %s", res, errtext);
		sqlite3_free(errtext);
		sqlite3_close(conn);
		free_module_options(options);
		return PAM_SESSION_ERR;
        }
	sqlite3_close(conn);
	DBGLOG("Session successfully opened !");
	free_module_options(options);
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct		module_options *options;
	int 		rc, res, std_flags;
	const char 	*user;
	sqlite3		*conn;
	char		*query, *errtext = NULL;
	                        
	std_flags = get_module_options(argc, argv, &options);
	if(options_valid(options) != 0) {
		free_module_options(options);
		return PAM_SESSION_ERR;
	}

	if ( ! options->sql_close_session ) {	/* If nothing has to be done, return SUCCESS anyway */
	        free_module_options(options);
	        return PAM_SUCCESS;
	}

	DBGLOG("Closing session ...");
	
	if((rc = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		free_module_options(options);
		return rc;
	}

	if(!(conn = pam_sqlite_connect(options))) {
		free_module_options(options);
		return PAM_SESSION_ERR;
	}

	query = format_query(options->sql_close_session, options, user, NULL);
	DBGLOG("query: %s", query);
	
	res = sqlite3_exec(conn, query, NULL, NULL, &errtext);
	free(query);

	if ( res != SQLITE_OK ) {
	        SYSLOG(LOG_ERR, "query failed[%d]: %s", res, errtext);
		sqlite3_free(errtext);
		sqlite3_close(conn);
		free_module_options(options);
		return PAM_SESSION_ERR;
        }
	sqlite3_close(conn);
	DBGLOG("Session successfully closed !");
	free_module_options(options);
	return PAM_SUCCESS;
}
