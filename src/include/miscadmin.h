/*-------------------------------------------------------------------------
 *
 * miscadmin.h
 *	  This file contains general postgres administration and initialization
 *	  stuff that used to be spread out between the following files:
 *		globals.h						global variables
 *		pdir.h							directory path crud
 *		pinit.h							postgres initialization
 *		pmod.h							processing modes
 *	  Over time, this has also become the preferred place for widely known
 *	  resource-limitation stuff, such as work_mem and check_stack_depth().
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/miscadmin.h
 *
 * NOTES
 *	  some of the information in this file should be moved to other files.
 *
 *-------------------------------------------------------------------------
 */
#ifndef MISCADMIN_H
#define MISCADMIN_H

#include <signal.h>

#include "pgtime.h"				/* for pg_time_t */


#define InvalidPid				(-1)


/*****************************************************************************
 *	  System interrupt and critical section handling
 *
 * There are two types of interrupts that a running backend needs to accept
 * without messing up its state: QueryCancel (SIGINT) and ProcDie (SIGTERM).
 * In both cases, we need to be able to clean up the current transaction
 * gracefully, so we can't respond to the interrupt instantaneously ---
 * there's no guarantee that internal data structures would be self-consistent
 * if the code is interrupted at an arbitrary instant.  Instead, the signal
 * handlers set flags that are checked periodically during execution.
 *
 * The CHECK_FOR_INTERRUPTS() macro is called at strategically located spots
 * where it is normally safe to accept a cancel or die interrupt.  In some
 * cases, we invoke CHECK_FOR_INTERRUPTS() inside low-level subroutines that
 * might sometimes be called in contexts that do *not* want to allow a cancel
 * or die interrupt.  The HOLD_INTERRUPTS() and RESUME_INTERRUPTS() macros
 * allow code to ensure that no cancel or die interrupt will be accepted,
 * even if CHECK_FOR_INTERRUPTS() gets called in a subroutine.  The interrupt
 * will be held off until CHECK_FOR_INTERRUPTS() is done outside any
 * HOLD_INTERRUPTS() ... RESUME_INTERRUPTS() section.
 *
 * There is also a mechanism to prevent query cancel interrupts, while still
 * allowing die interrupts: HOLD_CANCEL_INTERRUPTS() and
 * RESUME_CANCEL_INTERRUPTS().
 *
 * Special mechanisms are used to let an interrupt be accepted when we are
 * waiting for a lock or when we are waiting for command input (but, of
 * course, only if the interrupt holdoff counter is zero).  See the
 * related code for details.
 *
 * A lost connection is handled similarly, although the loss of connection
 * does not raise a signal, but is detected when we fail to write to the
 * socket. If there was a signal for a broken connection, we could make use of
 * it by setting ClientConnectionLost in the signal handler.
 *
 * A related, but conceptually distinct, mechanism is the "critical section"
 * mechanism.  A critical section not only holds off cancel/die interrupts,
 * but causes any ereport(ERROR) or ereport(FATAL) to become ereport(PANIC)
 * --- that is, a system-wide reset is forced.  Needless to say, only really
 * *critical* code should be marked as a critical section!	Currently, this
 * mechanism is only used for XLOG-related code.
 *
 *****************************************************************************/

/* in globals.c */
/* these are marked volatile because they are set by signal handlers: */
extern session_local PGDLLIMPORT volatile bool InterruptPending;
extern session_local PGDLLIMPORT volatile bool QueryCancelPending;
extern session_local PGDLLIMPORT volatile bool ProcDiePending;
extern session_local PGDLLIMPORT volatile bool IdleInTransactionSessionTimeoutPending;
extern session_local PGDLLIMPORT volatile sig_atomic_t ConfigReloadPending;

extern session_local volatile bool ClientConnectionLost;

/* these are marked volatile because they are examined by signal handlers: */
extern session_local PGDLLIMPORT volatile uint32 InterruptHoldoffCount;
extern session_local PGDLLIMPORT volatile uint32 QueryCancelHoldoffCount;
extern session_local PGDLLIMPORT volatile uint32 CritSectionCount;

/* in tcop/postgres.c */
extern void ProcessInterrupts(void);

#ifndef WIN32

#define CHECK_FOR_INTERRUPTS() \
do { \
	if (InterruptPending) \
		ProcessInterrupts(); \
} while(0)
#else							/* WIN32 */

#define CHECK_FOR_INTERRUPTS() \
do { \
	if (UNBLOCKED_SIGNAL_QUEUE()) \
		pgwin32_dispatch_queued_signals(); \
	if (InterruptPending) \
		ProcessInterrupts(); \
} while(0)
#endif							/* WIN32 */


#define HOLD_INTERRUPTS()  (InterruptHoldoffCount++)

#define RESUME_INTERRUPTS() \
do { \
	Assert(InterruptHoldoffCount > 0); \
	InterruptHoldoffCount--; \
} while(0)

#define HOLD_CANCEL_INTERRUPTS()  (QueryCancelHoldoffCount++)

#define RESUME_CANCEL_INTERRUPTS() \
do { \
	Assert(QueryCancelHoldoffCount > 0); \
	QueryCancelHoldoffCount--; \
} while(0)

#define START_CRIT_SECTION()  (CritSectionCount++)

#define END_CRIT_SECTION() \
do { \
	Assert(CritSectionCount > 0); \
	CritSectionCount--; \
} while(0)


/*****************************************************************************
 *	  globals.h --															 *
 *****************************************************************************/

/*
 * from utils/init/globals.c
 */
extern PGDLLIMPORT pthread_t PostmasterPid;
extern session_local PGDLLIMPORT bool IsPostmaster;
extern session_local PGDLLIMPORT bool IsPostmasterEnvironment;
extern session_local PGDLLIMPORT bool IsUnderPostmaster;
extern session_local PGDLLIMPORT bool IsBackgroundWorker;
extern session_local PGDLLIMPORT bool IsBinaryUpgrade;

extern session_local bool ExitOnAnyError;

extern session_local PGDLLIMPORT char *DataDir;

extern session_local PGDLLIMPORT int NBuffers;
extern session_local int	MaxBackends;
extern session_local int	MaxConnections;
extern session_local int	max_worker_processes;
extern session_local int	max_parallel_workers;

extern session_local PGDLLIMPORT pthread_t MyProcPid;
extern session_local PGDLLIMPORT pg_time_t MyStartTime;
extern session_local PGDLLIMPORT struct Port *MyProcPort;
extern session_local PGDLLIMPORT struct Latch *MyLatch;
extern session_local int32 MyCancelKey;
extern session_local int	MyPMChildSlot;

extern session_local char OutputFileName[];
extern session_local PGDLLIMPORT char my_exec_path[];
extern session_local char pkglib_path[];

#ifdef EXEC_BACKEND
extern session_local char postgres_exec_path[];
#endif

/*
 * done in storage/backendid.h for now.
 *
 * extern BackendId    MyBackendId;
 */
extern session_local PGDLLIMPORT Oid MyDatabaseId;

extern session_local PGDLLIMPORT Oid MyDatabaseTableSpace;

/*
 * Date/Time Configuration
 *
 * DateStyle defines the output formatting choice for date/time types:
 *	USE_POSTGRES_DATES specifies traditional Postgres format
 *	USE_ISO_DATES specifies ISO-compliant format
 *	USE_SQL_DATES specifies Oracle/Ingres-compliant format
 *	USE_GERMAN_DATES specifies German-style dd.mm/yyyy
 *
 * DateOrder defines the field order to be assumed when reading an
 * ambiguous date (anything not in YYYY-MM-DD format, with a four-digit
 * year field first, is taken to be ambiguous):
 *	DATEORDER_YMD specifies field order yy-mm-dd
 *	DATEORDER_DMY specifies field order dd-mm-yy ("European" convention)
 *	DATEORDER_MDY specifies field order mm-dd-yy ("US" convention)
 *
 * In the Postgres and SQL DateStyles, DateOrder also selects output field
 * order: day comes before month in DMY style, else month comes before day.
 *
 * The user-visible "DateStyle" run-time parameter subsumes both of these.
 */

/* valid DateStyle values */
#define USE_POSTGRES_DATES		0
#define USE_ISO_DATES			1
#define USE_SQL_DATES			2
#define USE_GERMAN_DATES		3
#define USE_XSD_DATES			4

/* valid DateOrder values */
#define DATEORDER_YMD			0
#define DATEORDER_DMY			1
#define DATEORDER_MDY			2

extern session_local PGDLLIMPORT int DateStyle;
extern session_local PGDLLIMPORT int DateOrder;

/*
 * IntervalStyles
 *	 INTSTYLE_POSTGRES			   Like Postgres < 8.4 when DateStyle = 'iso'
 *	 INTSTYLE_POSTGRES_VERBOSE	   Like Postgres < 8.4 when DateStyle != 'iso'
 *	 INTSTYLE_SQL_STANDARD		   SQL standard interval literals
 *	 INTSTYLE_ISO_8601			   ISO-8601-basic formatted intervals
 */
#define INTSTYLE_POSTGRES			0
#define INTSTYLE_POSTGRES_VERBOSE	1
#define INTSTYLE_SQL_STANDARD		2
#define INTSTYLE_ISO_8601			3

extern session_local PGDLLIMPORT int IntervalStyle;

#define MAXTZLEN		10		/* max TZ name len, not counting tr. null */

extern session_local bool enableFsync;
extern session_local bool allowSystemTableMods;
extern session_local PGDLLIMPORT int work_mem;
extern session_local PGDLLIMPORT int maintenance_work_mem;

extern session_local int	VacuumCostPageHit;
extern session_local int	VacuumCostPageMiss;
extern session_local int	VacuumCostPageDirty;
extern session_local int	VacuumCostLimit;
extern session_local int	VacuumCostDelay;

extern session_local int	VacuumPageHit;
extern session_local int	VacuumPageMiss;
extern session_local int	VacuumPageDirty;

extern session_local int	VacuumCostBalance;
extern session_local bool VacuumCostActive;


/* in tcop/postgres.c */

#if defined(__ia64__) || defined(__ia64)
typedef struct
{
	char	   *stack_base_ptr;
	char	   *register_stack_base_ptr;
} pg_stack_base_t;
#else
typedef char *pg_stack_base_t;
#endif

extern pg_stack_base_t set_stack_base(void);
extern void restore_stack_base(pg_stack_base_t base);
extern void check_stack_depth(void);
extern bool stack_is_too_deep(void);

extern void PostgresSigHupHandler(SIGNAL_ARGS);

/* in tcop/utility.c */
extern void PreventCommandIfReadOnly(const char *cmdname);
extern void PreventCommandIfParallelMode(const char *cmdname);
extern void PreventCommandDuringRecovery(const char *cmdname);

/* in utils/misc/guc.c */
extern session_local int	trace_recovery_messages;
extern int	trace_recovery(int trace_level);

/*****************************************************************************
 *	  pdir.h --																 *
 *			POSTGRES directory path definitions.                             *
 *****************************************************************************/

/* flags to be OR'd to form sec_context */
#define SECURITY_LOCAL_USERID_CHANGE	0x0001
#define SECURITY_RESTRICTED_OPERATION	0x0002
#define SECURITY_NOFORCE_RLS			0x0004

extern session_local char *DatabasePath;

/* now in utils/init/miscinit.c */
extern void InitPostmasterChild(void);
extern void InitStandaloneProcess(const char *argv0);

extern void SetDatabasePath(const char *path);

extern char *GetUserNameFromId(Oid roleid, bool noerr);
extern Oid	GetUserId(void);
extern Oid	GetOuterUserId(void);
extern Oid	GetSessionUserId(void);
extern Oid	GetAuthenticatedUserId(void);
extern void GetUserIdAndSecContext(Oid *userid, int *sec_context);
extern void SetUserIdAndSecContext(Oid userid, int sec_context);
extern bool InLocalUserIdChange(void);
extern bool InSecurityRestrictedOperation(void);
extern bool InNoForceRLSOperation(void);
extern void GetUserIdAndContext(Oid *userid, bool *sec_def_context);
extern void SetUserIdAndContext(Oid userid, bool sec_def_context);
extern void InitializeSessionUserId(const char *rolename, Oid useroid);
extern void InitializeSessionUserIdStandalone(void);
extern void SetSessionAuthorization(Oid userid, bool is_superuser);
extern Oid	GetCurrentRoleId(void);
extern void SetCurrentRoleId(Oid roleid, bool is_superuser);

extern void SetDataDir(const char *dir);
extern void ChangeToDataDir(void);

extern void SwitchToSharedLatch(void);
extern void SwitchBackToLocalLatch(void);

/* in utils/misc/superuser.c */
extern bool superuser(void);	/* current user is superuser */
extern bool superuser_arg(Oid roleid);	/* given user is superuser */


/*****************************************************************************
 *	  pmod.h --																 *
 *			POSTGRES processing mode definitions.                            *
 *****************************************************************************/

/*
 * Description:
 *		There are three processing modes in POSTGRES.  They are
 * BootstrapProcessing or "bootstrap," InitProcessing or
 * "initialization," and NormalProcessing or "normal."
 *
 * The first two processing modes are used during special times. When the
 * system state indicates bootstrap processing, transactions are all given
 * transaction id "one" and are consequently guaranteed to commit. This mode
 * is used during the initial generation of template databases.
 *
 * Initialization mode: used while starting a backend, until all normal
 * initialization is complete.  Some code behaves differently when executed
 * in this mode to enable system bootstrapping.
 *
 * If a POSTGRES backend process is in normal mode, then all code may be
 * executed normally.
 */

typedef enum ProcessingMode
{
	BootstrapProcessing,		/* bootstrap creation of template database */
	InitProcessing,				/* initializing system */
	NormalProcessing			/* normal processing */
} ProcessingMode;

extern session_local ProcessingMode Mode;

#define IsBootstrapProcessingMode() (Mode == BootstrapProcessing)
#define IsInitProcessingMode()		(Mode == InitProcessing)
#define IsNormalProcessingMode()	(Mode == NormalProcessing)

#define GetProcessingMode() Mode

#define SetProcessingMode(mode) \
	do { \
		AssertArg((mode) == BootstrapProcessing || \
				  (mode) == InitProcessing || \
				  (mode) == NormalProcessing); \
		Mode = (mode); \
	} while(0)


/*
 * Auxiliary-process type identifiers.  These used to be in bootstrap.h
 * but it seems saner to have them here, with the ProcessingMode stuff.
 * The MyAuxProcType global is defined and set in bootstrap.c.
 */

typedef enum
{
	NotAnAuxProcess = -1,
	CheckerProcess = 0,
	BootstrapProcess,
	StartupProcess,
	BgWriterProcess,
	CheckpointerProcess,
	WalWriterProcess,
	WalReceiverProcess,

	NUM_AUXPROCTYPES			/* Must be last! */
} AuxProcType;

extern session_local AuxProcType MyAuxProcType;

#define AmBootstrapProcess()		(MyAuxProcType == BootstrapProcess)
#define AmStartupProcess()			(MyAuxProcType == StartupProcess)
#define AmBackgroundWriterProcess() (MyAuxProcType == BgWriterProcess)
#define AmCheckpointerProcess()		(MyAuxProcType == CheckpointerProcess)
#define AmWalWriterProcess()		(MyAuxProcType == WalWriterProcess)
#define AmWalReceiverProcess()		(MyAuxProcType == WalReceiverProcess)


/*****************************************************************************
 *	  pinit.h --															 *
 *			POSTGRES initialization and cleanup definitions.                 *
 *****************************************************************************/

/* in utils/init/postinit.c */
extern void pg_split_opts(char **argv, int *argcp, const char *optstr);
extern void InitializeMaxBackends(void);
extern void InitPostgres(const char *in_dbname, Oid dboid, const char *username,
			 Oid useroid, char *out_dbname);
extern void BaseInit(void);

/* in utils/init/miscinit.c */
extern session_local bool IgnoreSystemIndexes;
extern session_local PGDLLIMPORT bool process_shared_preload_libraries_in_progress;
extern session_local char *session_preload_libraries_string;
extern session_local char *shared_preload_libraries_string;
extern session_local char *local_preload_libraries_string;

extern void CreateDataDirLockFile(bool amPostmaster);
extern void CreateSocketLockFile(const char *socketfile, bool amPostmaster,
					 const char *socketDir);
extern void TouchSocketLockFiles(void);
extern void AddToDataDirLockFile(int target_line, const char *str);
extern bool RecheckDataDirLockFile(void);
extern void ValidatePgVersion(const char *path);
extern void process_shared_preload_libraries(void);
extern void process_session_preload_libraries(void);
extern void pg_bindtextdomain(const char *domain);
extern bool has_rolreplication(Oid roleid);

/* in access/transam/xlog.c */
extern bool BackupInProgress(void);
extern void CancelBackup(void);

#endif							/* MISCADMIN_H */
