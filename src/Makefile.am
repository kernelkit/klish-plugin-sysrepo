plugindir = ${libdir}/@PLUGINS_SUBDIR@
plugin_LTLIBRARIES =

plugin_LTLIBRARIES += kplugin-sysrepo.la
kplugin_sysrepo_la_SOURCES =
kplugin_sysrepo_la_LDFLAGS = $(AM_LDFLAGS) -avoid-version -module
kplugin_sysrepo_la_LIBS =
kplugin_sysrepo_la_CFLAGS = $(AM_CFLAGS)
#kplugin_sysrepo_la_LIBADD = libsysrepo.la

kplugin_sysrepo_la_SOURCES += \
	src/plugin.c \
	src/private.h \
	src/syms.c \
	src/show.c \
	src/pline.h \
	src/pline.c \
	src/kly.c
