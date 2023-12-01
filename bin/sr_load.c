#include <stdlib.h>
#include <stdio.h>

#include <faux/faux.h>
#include <faux/str.h>
#include <faux/file.h>
#include <faux/argv.h>

#include <sysrepo.h>
#include <sysrepo/xpath.h>

#include "pline.h"


int main(int argc, char **argv)
{
	int ret = -1;
	int err = SR_ERR_OK;
	sr_conn_ctx_t *conn = NULL;
	sr_session_ctx_t *sess = NULL;
	faux_file_t *file = NULL;
	char *line = NULL;
	pline_opts_t opts;

	err = sr_connect(SR_CONN_DEFAULT, &conn);
	if (err) {
		fprintf(stderr, "Error: Can't connect to sysrepo\n");
		goto out;
	}
	err = sr_session_start(conn, SR_DS_RUNNING, &sess);
	if (err) {
		fprintf(stderr, "Error: Can't start session\n");
		goto out;
	}

	file = faux_file_fdopen(STDIN_FILENO);
	if (!file) {
		fprintf(stderr, "Error: Can't open stdin\n");
		goto out;
	}

	pline_opts_init(&opts);

	while ((line = faux_file_getline(file))) {
		pline_t *pline = NULL;
		faux_argv_t *args = NULL;

		args = faux_argv_new();
		faux_argv_parse(args, line);
		pline = pline_parse(sess, args, &opts);
		faux_argv_free(args);
		if (!pline || pline->invalid) {
			fprintf(stderr, "Invalid line: %s\n", line);
		} else {
			pline_debug(pline);
			printf("pline\n");
//			pline_print_completions(pline, BOOL_TRUE, PT_COMPL_ALL);
		}
		pline_free(pline);
		faux_str_free(line);
	}

/*
	faux_argv_t *args = faux_argv_new();
	faux_argv_parse(args, argv[1]);
	faux_argv_del_continuable(args);
	pline = pline_parse(sess, args, 0);
	faux_argv_free(args);
	pline_debug(pline);
	pline_print_completions(pline, BOOL_TRUE, PT_COMPL_ALL);
	pline_free(pline);
*/
	ret = 0;
out:
	faux_file_close(file);
	sr_disconnect(conn);

	argc = argc;
	argv = argv;

	return ret;
}
