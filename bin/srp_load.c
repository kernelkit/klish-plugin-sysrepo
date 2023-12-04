#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <getopt.h>

#include <faux/faux.h>
#include <faux/str.h>
#include <faux/file.h>
#include <faux/argv.h>

#include <sysrepo.h>
#include <sysrepo/xpath.h>
#include <sysrepo/netconf_acm.h>

#include "klish_plugin_sysrepo.h"

#ifndef VERSION
#define VERSION "1.0.0"
#endif

#define DEFAULT_USER "root"
#define DEFAULT_DATASTORE SR_DS_CANDIDATE

typedef struct cmd_opts_s {
	bool_t verbose;
	char *cfg;
	char *file;
	char *user;
	bool_t stop_on_error;
	sr_datastore_t datastore;
} cmd_opts_t;


int srp_mass_set(int fd, sr_datastore_t ds, pline_opts_t *opts,
	const char *user, bool_t stop_on_error);

// Command line options
static cmd_opts_t *cmd_opts_init(void);
static void cmd_opts_free(cmd_opts_t *opts);
static int cmd_opts_parse(int argc, char *argv[], cmd_opts_t *opts);
static void help(int status, const char *argv0);


int main(int argc, char **argv)
{
	int ret = -1;
	pline_opts_t opts;
	cmd_opts_t *cmd_opts = NULL;
	int fd = STDIN_FILENO;

	cmd_opts = cmd_opts_init();
	if (cmd_opts_parse(argc, argv, cmd_opts) < 0) {
		fprintf(stderr, "Error: Illegal command line options\n");
		goto out;
	}

	if (cmd_opts->file) {
		fd = open(cmd_opts->file, O_RDONLY, 0);
		if (fd < 0) {
			fprintf(stderr, "Error: Can't open \"%s\"\n", cmd_opts->file);
			goto out;
		}
	}

	pline_opts_init(&opts);
	ret = srp_mass_set(fd, cmd_opts->datastore, &opts,
		cmd_opts->user, cmd_opts->stop_on_error);

out:
	if (cmd_opts->file)
		close(fd);
	cmd_opts_free(cmd_opts);

	return ret;
}


int srp_mass_set(int fd, sr_datastore_t ds, pline_opts_t *opts,
	const char *user, bool_t stop_on_error)
{
	int ret = -1;
	int err = SR_ERR_OK;
	sr_conn_ctx_t *conn = NULL;
	sr_session_ctx_t *sess = NULL;
	faux_file_t *file = NULL;
	char *line = NULL;
	size_t err_num = 0;
	sr_subscription_ctx_t *nacm_sub = NULL;

	err = sr_connect(SR_CONN_DEFAULT, &conn);
	if (err) {
		fprintf(stderr, "Error: Can't connect to sysrepo\n");
		goto out;
	}
	err = sr_session_start(conn, ds, &sess);
	if (err) {
		fprintf(stderr, "Error: Can't start session\n");
		goto out;
	}

	sr_session_set_orig_name(sess, user);
	// Init NACM session
	if (opts->enable_nacm) {
		if (sr_nacm_init(sess, 0, &nacm_sub) != SR_ERR_OK) {
			fprintf(stderr, "Error: Can't init NACM\n");
			goto out;
		}
		sr_nacm_set_user(sess, user);
	}

	file = faux_file_fdopen(fd);
	if (!file) {
		fprintf(stderr, "Error: Can't open input stream\n");
		goto out;
	}

	while ((line = faux_file_getline(file))) {
		pline_t *pline = NULL;
		faux_argv_t *args = NULL;

		args = faux_argv_new();
		faux_argv_parse(args, line);
		pline = pline_parse(sess, args, opts);
		faux_argv_free(args);
		if (!pline || pline->invalid) {
			err_num++;
			fprintf(stderr, "Error: Illegal: %s\n", line);
		} else {
			faux_list_node_t *iter = NULL;
			pexpr_t *expr = NULL;

			iter = faux_list_head(pline->exprs);
			while ((expr = (pexpr_t *)faux_list_each(&iter))) {
				if (!(expr->pat & PT_SET)) {
					err_num++;
					fprintf(stderr, "Error: Illegal expression for set operation\n");
					break;
				}
				if (sr_set_item_str(sess, expr->xpath, expr->value, NULL, 0) !=
					SR_ERR_OK) {
					err_num++;
					fprintf(stderr, "Error: Can't set data\n");
					break;
				}
			}
		}
		if (stop_on_error && (err_num > 0)) {
			sr_discard_changes(sess);
			goto out;
		}
		pline_free(pline);
		faux_str_free(line);
	}

	if (sr_has_changes(sess)) {
		if (sr_apply_changes(sess, 0) != SR_ERR_OK) {
			sr_discard_changes(sess);
			fprintf(stderr, "Error: Can't apply changes\n");
			goto out;
		}
	}

	ret = 0;
out:
	faux_file_close(file);
	if (opts->enable_nacm) {
		sr_unsubscribe(nacm_sub);
		sr_nacm_destroy();
	}
	sr_disconnect(conn);

	return ret;
}


static cmd_opts_t *cmd_opts_init(void)
{
	cmd_opts_t *opts = NULL;

	opts = faux_zmalloc(sizeof(*opts));
	assert(opts);

	// Initialize
	opts->verbose = BOOL_FALSE;
	opts->stop_on_error = BOOL_FALSE;
	opts->cfg = NULL;
	opts->file = NULL;
	opts->user = NULL;
	opts->datastore = DEFAULT_DATASTORE;

	return opts;
}


static void cmd_opts_free(cmd_opts_t *opts)
{
	if (!opts)
		return;
	faux_str_free(opts->cfg);
	faux_str_free(opts->file);
	faux_str_free(opts->user);

	faux_free(opts);
}


static int cmd_opts_parse(int argc, char *argv[], cmd_opts_t *opts)
{
	static const char *shortopts = "hf:veu:d:";
	static const struct option longopts[] = {
		{"conf",		1, NULL, 'f'},
		{"help",		0, NULL, 'h'},
		{"verbose",		0, NULL, 'v'},
		{"user",		1, NULL, 'u'},
		{"stop-on-error",	0, NULL, 'e'},
		{"datastore",		1, NULL, 'd'},
		{NULL,			0, NULL, 0}
	};

	optind = 1;
	while(1) {
		int opt = 0;

		opt = getopt_long(argc, argv, shortopts, longopts, NULL);
		if (-1 == opt)
			break;
		switch (opt) {
		case 'v':
			opts->verbose = BOOL_TRUE;
			break;
		case 'e':
			opts->stop_on_error = BOOL_TRUE;
			break;
		case 'h':
			help(0, argv[0]);
			_exit(0);
			break;
		case 'u':
			faux_str_free(opts->user);
			opts->user = faux_str_dup(optarg);
			break;
		case 'f':
			faux_str_free(opts->cfg);
			opts->cfg = faux_str_dup(optarg);
			break;
		case 'd':
			if (!kly_str2ds(optarg, strlen(optarg), &opts->datastore))
				return BOOL_FALSE;
			break;
		default:
			help(-1, argv[0]);
			_exit(-1);
			break;
		}
	}

	// Input file
	if(optind < argc) {
		faux_str_free(opts->file);
		opts->file = faux_str_dup(argv[optind]);
	}

	// Validate options
	if (!opts->user)
		opts->user = faux_str_dup(DEFAULT_USER);

	return 0;
}


static void help(int status, const char *argv0)
{
	const char *name = NULL;

	if (!argv0)
		return;

	// Find the basename
	name = strrchr(argv0, '/');
	if (name)
		name++;
	else
		name = argv0;

	if (status != 0) {
		fprintf(stderr, "Try `%s -h' for more information.\n",
			name);
	} else {
		printf("Version : %s\n", VERSION);
		printf("Usage   : %s [options] [filename]\n", name);
		printf("Load mass of config strings to Sysrepo repository\n");
		printf("Options :\n");
		printf("\t-h, --help Print this help.\n");
		printf("\t-v, --verbose Be verbose.\n");
		printf("\t-e, --stop-on-error Stop script execution on error.\n");
		printf("\t-u <name>, --user=<name> NACM user.\n");
		printf("\t-f <path>, --conf=<path> Config file.\n");
		printf("\t-d <ds>, --datastore=<ds> Datastore.\n");
	}
}
