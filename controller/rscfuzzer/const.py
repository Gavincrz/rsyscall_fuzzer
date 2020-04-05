import signal
import re

ACCEPT_SIG = int(signal.SIGRTMAX-7)
CLIENT_DELAY = 1

''' gdb patterns '''
top_stack_pattern = re.compile("#.*")
at_pattern = re.compile("#.* at .*")
not_found_pattern = re.compile(".*No such file or directory.*")
empty_history_pattern = re.compile(".*The history is empty.*")
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
               "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", ]









