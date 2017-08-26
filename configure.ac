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

have_ncurses_header=n
have_ncurses_lib=n
AC_CHECK_HEADERS([ncurses.h],[have_ncurses_header=y])
AC_CHECK_LIB(ncurses,initscr,[have_ncurses_lib=y])
if test "x${have_ncurses_header}${have_ncurses_lib}" != xyy
then
  AM_CONDITIONAL(HAVE_NCURSES,false)
else
  AM_CONDITIONAL(HAVE_NCURSES,true)
fi


have_pcre_header=n
have_pcre_lib=n
AC_CHECK_HEADERS([pcre.h],[have_pcre_header=y])
AC_CHECK_LIB(pcre,pcre_exec,[have_pcre_lib=y])
if test "x${have_pcre_header}${have_pcre_lib}" != xyy
then
  AM_CONDITIONAL(HAVE_PCRE,false)
else
  AM_CONDITIONAL(HAVE_PCRE,true)
fi

have_zlib_header=n
have_zlib_lib=n
AC_CHECK_HEADERS([zlib.h],[have_zlib_header=y])
AC_CHECK_LIB(z,deflate,[have_zlib_lib=y])
if test "x${have_zlib_header}${have_zlib_lib}" != xyy
then
  AM_CONDITIONAL(HAVE_ZLIB,false)
else
  AM_CONDITIONAL(HAVE_ZLIB,true)
fi

have_sqlite3_header=n
have_sqlite3_lib=n
AC_CHECK_HEADERS([sqlite3.h],[have_sqlite3_header=y])
AC_CHECK_LIB(sqlite3,sqlite3_open,[have_sqlite3_lib=y])
if test "x${have_sqlite3_header}${have_sqlite3_lib}" != xyy
then
  AM_CONDITIONAL(HAVE_SQLITE3,false)
else
  AM_CONDITIONAL(HAVE_SQLITE3,true)
fi

AC_CONFIG_FILES([Makefile
   util/Makefile
   lib/Makefile
   ])
AC_OUTPUT
