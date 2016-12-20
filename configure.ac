AC_INIT([fluxcap], 1.0)
AM_INIT_AUTOMAKE([foreign subdir-objects])
m4_ifdef([AM_SILENT_RULES],
    [AM_SILENT_RULES([yes])
    ])
AC_PROG_CC
AC_PROG_RANLIB

# is ncurses installed
AC_CHECK_LIB(ncurses,initscr,
  AM_CONDITIONAL(HAVE_NCURSES,true),
  AM_CONDITIONAL(HAVE_NCURSES,false))

AC_CONFIG_FILES([Makefile
   util/Makefile
   lib/Makefile
   lib/shr/Makefile])
AC_OUTPUT
