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

#include "klish_plugin_sysrepo.h"

#ifndef VERSION
#define VERSION "1.0.0"
#endif

#define DEFAULT_USER "root"
#define DEFAULT_DATASTORE SR_DS_CANDIDATE

typedef struct cmd_opts_s {
	char *cfg; // Configuration options
	char *file; // File to load
	char *user; // NACM user
	char *current_path; // Current sysrepo path
	bool_t verbose;
	bool_t stop_on_error;
	sr_datastore_t datastore;
} cmd_opts_t;


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
	faux_argv_t *cur_path = NULL;

	// Command line options parsing
	cmd_opts = cmd_opts_init();
	if (cmd_opts_parse(argc, argv, cmd_opts) < 0) {
		fprintf(stderr, "Error: Illegal command line options\n");
		goto out;
	}

	// Open input file
	if (cmd_opts->file) {
		fd = open(cmd_opts->file, O_RDONLY, 0);
		if (fd < 0) {
			fprintf(stderr, "Error: Can't open \"%s\"\n", cmd_opts->file);
			goto out;
		}
	}

	// Get pline options
	pline_opts_init(&opts);
	if (cmd_opts->cfg)
		pline_opts_parse_file(cmd_opts->cfg, &opts);

	// Prepare argv structure for current sysrepo path
	if (cmd_opts->current_path) {
		cur_path = faux_argv_new();
		faux_argv_parse(cur_path, cmd_opts->current_path);
	}

	ret = srp_mass_set(fd, cmd_opts->datastore, cur_path,
		&opts, cmd_opts->user, cmd_opts->stop_on_error);

out:
	if (cur_path)
		faux_argv_free(cur_path);
	if (cmd_opts->file)
		close(fd);
	cmd_opts_free(cmd_opts);

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
	opts->current_path = NULL;

	return opts;
}


static void cmd_opts_free(cmd_opts_t *opts)
{
	if (!opts)
		return;
	faux_str_free(opts->cfg);
	faux_str_free(opts->file);
	faux_str_free(opts->user);
	faux_str_free(opts->current_path);

	faux_free(opts);
}


static int cmd_opts_parse(int argc, char *argv[], cmd_opts_t *opts)
{
	static const char *shortopts = "hf:veu:d:p:";
	static const struct option longopts[] = {
		{"conf",		1, NULL, 'f'},
		{"help",		0, NULL, 'h'},
		{"verbose",		0, NULL, 'v'},
		{"user",		1, NULL, 'u'},
		{"stop-on-error",	0, NULL, 'e'},
		{"datastore",		1, NULL, 'd'},
		{"current-path",	1, NULL, 'p'},
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
		case 'p':
			faux_str_free(opts->current_path);
			opts->current_path = faux_str_dup(optarg);
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
		printf("\t-p <sr-path>, --current-path=<sr-path> Current sysrepo path.\n");
	}
}
