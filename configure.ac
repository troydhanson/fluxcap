AC_INIT([fluxcap], 1.0)
AM_INIT_AUTOMAKE([foreign subdir-objects])
m4_ifdef([AM_SILENT_RULES],
    [AM_SILENT_RULES([yes])
    ])
AC_PROG_CC
AC_PROG_RANLIB

have_shr_header=n
have_shr_lib=n
AC_CHECK_HEADERS([shr.h],[have_shr_header=y])
AC_CHECK_LIB(shr,shr_readv,[have_shr_lib=y])
if test "x${have_shr_header}${have_shr_lib}" != xyy
then
  AC_MSG_ERROR([
  -----------------------------------------------------
  The libshr build prerequisite was not found. Please
  see the build instructions, install libshr and retry.
  -----------------------------------------------------
  ])
fi

AC_CHECK_LIB(ncurses,initscr,
  AM_CONDITIONAL(HAVE_NCURSES,true),
    AM_CONDITIONAL(HAVE_NCURSES,false))

AC_CONFIG_FILES([Makefile
   util/Makefile
   lib/Makefile
   ])
AC_OUTPUT
