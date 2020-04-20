import signal
import re

ACCEPT_SIG = int(signal.SIGRTMAX-7)
CLIENT_DELAY = 1

''' gdb patterns '''
top_stack_pattern = re.compile("#.*")
at_pattern = re.compile("#.* at .*")
not_found_pattern = re.compile(".*No such file or directory.*")
empty_history_pattern = re.compile(".*The history is empty.*")
gdb_not_found = re.compile(".*File format not recognized.*")
enable_stack_trace = False

ignore_syscall = ['arch_prctl', 'rt_sigaction', 'munmap',
                  'futex', 'ioctl', 'rt_sigprocmask', 'brk',
                  'mmap', 'execve', 'fcntl', 'mprotect', 'prctl',
                  'shutdown', 'set_robust_list', 'umask', 'alarm', 'clone']
will_do = ['access', 'dup2', 'dup3', 'bind', 'accept4', 'epoll_create', 'dup']

all_syscall = ["read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek",
               "ioctl", "pread", "pwrite", "readv", "writev", "access", "pipe", "select",
               "dup", "dup2", "pause", "nanosleep", "getpid", "sendfile", "socket", "connect",
               "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", "listen",
               "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", 'uname', 'flock', 'fsync',
               'fdatasync', 'truncate', 'ftruncate', 'getdents', 'getcwd', 'chdir', 'fchdir', 'rename', 'mkdir',
               'rmdir', 'creat', 'link', 'unlink', 'symlink', 'readlink', 'chmod', 'fchmod', 'chown', 'fchown',
               'lchown', 'gettimeofday', 'getrlimit', 'getrusage', 'sysinfo', 'times', 'getuid', 'getgid', 'setuid',
               'setgid', 'geteuid', 'getegid', 'setpgid', 'getppid', 'getpgrp', 'setsid', 'setreuid', 'setregid',
               'getgroups', 'setgroups', 'setresuid', 'getresuid', 'setresgid', 'getresgid', 'getpgid', 'getsid',
               'utime', 'mknod', 'statfs', 'fstatfs', 'sysfs', 'setpriority', 'sched_setparam',
               'sched_setscheduler', 'mlock', 'munlock', 'mlockall', 'munlockall', 'vhangup',
               'pivot_root', 'setrlimit', 'chroot', 'sync', 'acct', 'settimeofday', 'mount',
               'umount2', 'swapon', 'swapoff', 'sethostname', 'setdomainname', 'iopl',
               'ioperm', 'gettid', 'readahead', 'setxattr', 'lsetxattr', 'fsetxattr',
               'getxattr', 'lgetxattr', 'fgetxattr', 'listxattr', 'llistxattr',
               'flistxattr', 'removexattr', 'lremovexattr', 'fremovexattr',
               'time', 'sched_setaffinity', 'epoll_create', 'getdents', 'posix_fadvise',
               'timer_delete', 'clock_settime', 'clock_gettime', 'clock_getres', 'clock_nanosleep',
               'exit_group', 'epoll_wait', 'epoll_ctl', 'tgkill', 'utimes', 'mq_unlink', 'mq_timedsend',
               'mq_timedreceive', 'mq_notify', 'mq_getsetattr', 'inotify_init', 'inotify_add_watch',
               'inotify_rm_watch', 'openat', 'mkdirat', 'mknodat', 'fchownat', 'futimesat', 'fstatat',
               'unlinkat', 'renameat', 'linkat', 'symlinkat', 'readlinkat', 'fchmodat', 'faccessat',
               'pselect', 'ppoll', 'splice', 'tee', 'sync_file_range', 'vmsplice', 'utimensat',
               'epoll_pwait', 'timerfd_create', 'eventfd', 'fallocate', 'timerfd_settime', 'timerfd_gettime',
               'accept4', 'eventfd', 'epoll_create1', 'dup3', 'pipe2', 'inotify_init1', 'preadv', 'pwritev',
               'recvmmsg', 'fanotify_init', 'fanotify_mark', 'prlimit', 'name_to_handle_at', 'open_by_handle_at',
               'clock_adjtime', 'syncfs', 'sendmmsg', 'setns']









