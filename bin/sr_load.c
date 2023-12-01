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
	size_t err_num = 0;
	bool_t stop_on_error = BOOL_TRUE;

	err = sr_connect(SR_CONN_DEFAULT, &conn);
	if (err) {
		fprintf(stderr, "Error: Can't connect to sysrepo\n");
		goto out;
	}
	err = sr_session_start(conn, SR_DS_CANDIDATE, &sess);
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
	sr_disconnect(conn);

	argc = argc;
	argv = argv;

	return ret;
}
