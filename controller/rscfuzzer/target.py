import paramiko
import logging
import warnings
import shutil
import memcached_udp
import urllib.request as request
import os
import shlex
import subprocess
import memcached_udp
import redis
# suppress warning and logs for paramiko
warnings.filterwarnings(action='ignore',module='.*paramiko.*')
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

log = logging.getLogger(__name__)


# client functions
def test_memcached_target():
    arg_test = shlex.split('/rsyscall_fuzzer/controller/memcached_client.py')
    try:
        ret = subprocess.run(arg_test, timeout=8)
    except Exception as e:
        return -1
    if ret is None: 
        return -1
    else:
        return ret.returncode

def test_openssh_target():
    arg_test = shlex.split('/rsyscall_fuzzer/controller/openssh_client.py')
    try:
        ret = subprocess.run(arg_test, timeout=8)
    except Exception as e:
        return -1
    if ret is None: 
        return -1
    else:
        return ret.returncode

def connect_memcached_client(a1=None, a2=None):
    try:
        client = memcached_udp.Client([('127.0.0.1', 11111)], response_timeout=3)
        client.set('key1', 'value1')
        r = client.get('key1')
        if r == 'value1':
            return 0
        else:
            return -1
    except Exception as e:
        # print(e)
        return -1

def openssh_simple_client():
    try:
        ssh = paramiko.SSHClient()
        ssh.load_host_keys("/root/.ssh/known_hosts")
        ssh.connect("localhost", port=8080, username="root", timeout=1, banner_timeout=1, auth_timeout=1)
        ssh.exec_command("exit", timeout=5)
        ssh.close()
    except Exception as err:
        # log.error(f"{err}")
        return -1
    else:
        return 0

# def simple_redis_client():
#     try:
#         r = redis.Redis(host='localhost', port=6379, db=0, socket_timeout=3)
#         if r.set('foo', 'bar') != True:
#             return -1
#         if r.get('foo') != b"bar":
#             return -1
#         r.close()
#     except Exception as err:
#         return -1
#     else:
#         return 0

def simple_redis_client():
    arg_test = shlex.split('/rsyscall_fuzzer/controller/redis_client.py')
    try:
        ret = subprocess.run(arg_test, timeout=5)
    except Exception as e:
        return -1
    if ret is None:
        return -1
    else:
        return ret.returncode

def simple_web_client():
    try:
        request.urlopen(
            'http://127.0.0.1:8090', timeout=1)
    except Exception as e:
        # print(f"error {e}")
        return -1
    else:
        return 0


def complex_lighttpd_client():
    try:
        request.urlopen(
            'http://127.0.0.1:8090', timeout=1)
        request.urlopen(
            'http://127.0.0.1:8090/download/dir2/hello_dir.txt', timeout=1)
        request.urlopen(
            'http://127.0.0.1:8090/hello.php', timeout=1)
    except Exception as e:
        # print(f"error {e}")
        return -1
    else:
        return 0


def clean_up_git():
    try:
        shutil.rmtree('/home/gavin/gittest')
    except FileNotFoundError:
        # print("Git Directory dose not exist")
        pass
    except Exception as e:
        print(e)


def clean_up_git_docker():
    try:
        shutil.rmtree('/test_repo')
    except FileNotFoundError:
        # print("Git Directory dose not exist")
        pass
    except Exception as e:
        print(e)

def git_init_setup():
    clean_up_git()
    os.mkdir('/home/gavin/gittest')


def git_add_setup():
    git_init_setup()
    args_init = shlex.split('git init')
    subprocess.run(args_init, cwd = '/home/gavin/gittest')
    # write file to git diretory
    content = os.urandom(1024)
    f = open("/home/gavin/gittest/testfile.txt", "wb")
    f.write(content)
    f.close()


def git_commit_setup():
    git_add_setup()
    args_add = shlex.split('git add -A')
    subprocess.run(args_add, cwd='/home/gavin/gittest')


def git_pull_setup():
    clean_up_git()
    shutil.copytree('/home/gavin/git_copy/FileTransfer', '/home/gavin/gittest')


def connect_memcached_client():
    try:
        client = memcached_udp.Client([('127.0.0.1', 11111)], response_timeout=3)
        client.set('key1', 'value1')
        r = client.get('key1')
    except Exception as e:
        return -1
    else:
        return 0


targets = {
    "openssh":
        {"command": "/home/gavin/openssh/sshd -f /home/gavin/ssh_trace/sshd_config -D -d",
         "server": True,
         "poll": "select",
         "clients": [openssh_simple_client],
         "sudo": True,
         "retcode": 255,
         "env": {"test1": "var1", "test2": "var2"},
         "strace_log": "openssh_strace_log.txt",
         "cwd": None,
         "input": None,
         "timeout": 5,
         "setup_func": None,
         "poll_time": 3,
         "cov": False,
         "sc_cov": True,
         "hash_file": "syscov_openssh.txt",
         },
    "openssh_cov":
        {"command": "/home/gavin/openssh_cov/sshd -f /home/gavin/ssh_trace/sshd_config -D -d",
         "server": True,
         "poll": "select",
         "clients": [openssh_simple_client],
         "sudo": True,
         "retcode": 255,
         "env": {"test1": "var1", "test2": "var2"},
         "strace_log": "openssh_strace_log.txt",
         "cwd": None,
         "input": None,
         "timeout": 5,
         "setup_func": None,
         "poll_time": 3,
         "cov": True,
         "cov_cwd": "/home/gavin/openssh_cov/",
         "fuzz_valid": False,
         },
    "openssh_sccov":
        {"command": "/home/gavin/openssh/sshd -f /home/gavin/ssh_trace/sshd_config -D -d",
         "server": True,
         "poll": "select",
         "clients": [openssh_simple_client],
         "sudo": True,
         "retcode": 255,
         "env": {"test1": "var1", "test2": "var2"},
         "strace_log": "openssh_strace_log.txt",
         "cwd": None,
         "input": None,
         "timeout": 5,
         "setup_func": None,
         "poll_time": 3,
         "cov": False,
         "sc_cov": True,
         "hash_file": "syscov_openssh.txt",
         "cov_cwd": "/home/gavin/openssh_cov/",
         "fuzz_valid": True,
         },
    "openssh_acov":
        {"command": "/home/gavin/openssh/sshd -f /home/gavin/ssh_trace/sshd_config -D -d",
         "server": True,
         "poll": "select",
         "clients": [openssh_simple_client],
         "sudo": True,
         "retcode": 255,
         "env": {"test1": "var1", "test2": "var2"},
         "strace_log": "openssh_strace_log.txt",
         "cwd": None,
         "input": None,
         "timeout": 5,
         "setup_func": None,
         "poll_time": 3,
         "cov": False,
         "sc_cov": True,
         "a_cov": True,
         "syscall_json": "/home/gavin/openssh_syscall.json",
         "hash_file": "syscov_openssh.txt",
         "cov_cwd": "/home/gavin/openssh_cov/",
         "fuzz_valid": True,
         },
    "cov_test":
        {"command": "/home/gavin/simpletest/cov-test/test",
         "server": False,
         "poll": None,
         "clients": None,
         "sudo": True,
         "retcode": None,
         "env": {"test1": "var1", "test2": "var2"},
         "strace_log": "cov_test_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 5,
         "setup_func": None,
         "poll_time": None,
         },
    "lighttpd":
        {"command": "/home/gavin/lighttpd-1.4.51/src/lighttpd "
                    "-D -f /home/gavin/lighttpd-1.4.51/doc/config/lighttpd.conf",
         "server": True,
         "poll": "epoll_wait",
         "clients": [simple_web_client],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "lighttpd_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 5,
         "setup_func": None,
         "poll_time": 3,
         "sc_cov": True,
         "hash_file": "syscov_lighttpd.txt",
         "cov": False
         },
    "lighttpd_sccov":
        {"command": "/home/gavin/lighttpd-1.4.51/src/lighttpd "
                    "-D -f /home/gavin/lighttpd-1.4.51/doc/config/lighttpd.conf",
         "server": True,
         "poll": "epoll_wait",
         "clients": [simple_web_client],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "lighttpd_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 5,
         "setup_func": None,
         "poll_time": 3,
         "cov": False,
         "sc_cov": True,
         "hash_file": "syscov_lighttpd.txt",
         "cov_cwd": "/home/gavin/openssh_cov/",
         "fuzz_valid": True,
         },
    "lighttpd_acov":
        {"command": "/home/gavin/lighttpd-1.4.51/src/lighttpd "
                    "-D -f /home/gavin/lighttpd-1.4.51/doc/config/lighttpd.conf",
         "server": True,
         "poll": "epoll_wait",
         "clients": [simple_web_client],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "lighttpd_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 5,
         "setup_func": None,
         "poll_time": 1,
         "cov": False,
         "sc_cov": True,
         "a_cov": True,
         "syscall_json": "/home/gavin/lighttpd_syscall.json",
         "hash_file": "syscov_lighttpd.txt",
         "cov_cwd": "/home/gavin/openssh_cov/",
         "fuzz_valid": True,
         },
    "lighttpd_cov":
        {"command": "/home/gavin/lighttpd-cov/src/lighttpd "
                    "-D -f /home/gavin/lighttpd-1.4.51/doc/config/lighttpd.conf",
         "server": True,
         "poll": "epoll_wait",
         "clients": [simple_web_client],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "lighttpd_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 5,
         "setup_func": None,
         "poll_time": 3,
         "cov": True,
         "cov_cwd": "/home/gavin/lighttpd-cov/",
         "fuzz_valid": False,
         },

    "lighttpd_sccov_complex":
        {"command": "/home/gavin/lighttpd-1.4.51/src/lighttpd "
                    "-D -f /home/gavin/lighttpd-1.4.51/doc/config/lighttpd_complex.conf",
         "server": True,
         "poll": "epoll_wait",
         "clients": [complex_lighttpd_client],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "lighttpd_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 8,
         "setup_func": None,
         "poll_time": 5,
         "cov": False,
         "cov_cwd": "/home/gavin/lighttpd-cov/",
         "fuzz_valid": True,
         "sc_cov": True,
         "hash_file": "syscov_lighttpd_complex.txt",
         },
    "lighttpd_acov_complex":
        {"command": "/home/gavin/lighttpd-1.4.51/src/lighttpd "
                    "-D -f /home/gavin/lighttpd-1.4.51/doc/config/lighttpd_complex.conf",
         "server": True,
         "poll": "epoll_wait",
         "clients": [complex_lighttpd_client],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "lighttpd_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 8,
         "setup_func": None,
         "poll_time": 5,
         "cov": False,
         "a_cov": True,
         "cov_cwd": "/home/gavin/lighttpd-cov/",
         "fuzz_valid": True,
         "sc_cov": True,
         "syscall_json": "/home/gavin/lighttpd_syscall.json",
         "hash_file": "syscov_lighttpd_complex.txt",
         },
    "lighttpd_cov_complex":
        {"command": "/home/gavin/lighttpd-cov/src/lighttpd "
                    "-D -f /home/gavin/lighttpd-1.4.51/doc/config/lighttpd_complex.conf",
         "server": True,
         "poll": "epoll_wait",
         "clients": [complex_lighttpd_client],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "lighttpd_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 5,
         "setup_func": None,
         "poll_time": 3,
         "cov": False,
         "cov_cwd": "/home/gavin/lighttpd-cov/",
         "fuzz_valid": True,
         },
    "zlib_cov":
        {"command": "/home/gavin/zlib_cov/example",
         "server": False,
         "poll": None,
         "clients": [],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "zlib_cov_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 10,
         "setup_func": None,
         "poll_time": 3,
         "cov": True,
         "cov_cwd": "/home/gavin/zlib_cov/",
         "fuzz_valid": True,
         },
    "zlib_sccov":
        {"command": "/home/gavin/zlib/example",
         "server": False,
         "poll": None,
         "clients": [],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "zlib_cov_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 15,
         "setup_func": None,
         "poll_time": 3,
         "cov": False,
         "cov_cwd": "/home/gavin/zlib_cov/",
         "fuzz_valid": False,
         "sc_cov": True,
         "hash_file": "syscov_lighttpd_complex.txt",
         },

    "zlib_acov":
        {"command": "/home/gavin/zlib/example",
         "server": False,
         "poll": None,
         "clients": [],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "zlib_cov_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 15,
         "setup_func": None,
         "poll_time": 3,
         "cov": False,
         "cov_cwd": "/home/gavin/zlib_cov/",
         "fuzz_valid": True,
         "a_cov": True,
         "sc_cov": True,
         "syscall_json": "/home/gavin/zlib_syscall.json",
         "hash_file": "syscov_lighttpd_complex.txt",
         },

    "memcached_sccov":
        {"command": "/home/gavin/memcached-1.5.20/memcached -p 11111 -U 11111 -u gavin",
         "server": True,
         "poll": "epoll_wait",
         "clients": [connect_memcached_client],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "memcached_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 8,
         "setup_func": None,
         "poll_time": 5,
         "cov": False,
         "a_cov": True,
         "cov_cwd": "/home/gavin/memcached-cov/",
         "fuzz_valid": True,
         "sc_cov": True,
         "syscall_json": "/home/gavin/memcached_syscall.json",
         "hash_file": "syscov_memcached.txt",
         },

    "git_sccov":
        {"command": "/home/gavin/git-2.18.0/git clone gavin@localhost:gittest_remote.git /home/gavin/gittest/",
         "server": False,
         "poll": None,
         "clients": [],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "git_sccov_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 15,
         "setup_func": clean_up_git,
         "poll_time": 3,
         "fuzz_valid": True,
         "a_cov": True,
         "sc_cov": True,
         "syscall_json": "/home/gavin/git_syscall.json",
         "hash_file": "syscov_git.txt",
         },
    "git":
        {"command": "/home/gavin/git-2.18.0/git clone gavin@localhost:gittest_remote.git /home/gavin/gittest/",
         "server": False,
         "poll": None,
         "clients": [],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "git_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 15,
         "setup_func": clean_up_git,
         "poll_time": 3,
         "fuzz_valid": False,
         # "a_cov": True,
         "sc_cov": True,
         # "syscall_json": "/home/gavin/git_syscall.json",
         "hash_file": "syscov_git.txt",
         },
    "git_init_sccov":
        {"command": "/home/gavin/git-2.18.0/git init",
         "server": False,
         "poll": None,
         "clients": [],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "git_sccov_strace.txt",
         "cwd": "/home/gavin/gittest",
         "input": None,
         "timeout": 15,
         "setup_func": git_init_setup,
         "poll_time": 3,
         "fuzz_valid": True,
         "a_cov": True,
         "sc_cov": True,
         "syscall_json": "/home/gavin/git_syscall.json",
         "hash_file": "syscov_git.txt",
         },

    "git_add_sccov":
        {"command": "/home/gavin/git-2.18.0/git add -A",
         "server": False,
         "poll": None,
         "clients": [],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "git_sccov_strace.txt",
         "cwd": "/home/gavin/gittest",
         "input": None,
         "timeout": 15,
         "setup_func": git_add_setup,
         "poll_time": 3,
         "fuzz_valid": True,
         "a_cov": True,
         "sc_cov": True,
         "syscall_json": "/home/gavin/git_syscall.json",
         "hash_file": "syscov_git.txt",
         "num_iteration": 5,
         },

    "git_commit_sccov":
        {"command": "/home/gavin/git-2.18.0/git commit -m 'test commit'",
         "server": False,
         "poll": None,
         "clients": [],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "git_sccov_strace.txt",
         "cwd": "/home/gavin/gittest",
         "input": None,
         "timeout": 15,
         "setup_func": git_commit_setup,
         "poll_time": 3,
         "fuzz_valid": True,
         "a_cov": True,
         "sc_cov": True,
         "syscall_json": "/home/gavin/git_syscall.json",
         "hash_file": "syscov_git.txt",
         "num_iteration": 5,
         },

    "git_pull_sccov":
        {"command": "/home/gavin/git-2.18.0/git pull",
         "server": False,
         "poll": None,
         "clients": [],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "git_sccov_strace.txt",
         "cwd": "/home/gavin/gittest",
         "input": None,
         "timeout": 15,
         "setup_func": git_pull_setup,
         "poll_time": 3,
         "fuzz_valid": True,
         "a_cov": True,
         "sc_cov": True,
         "syscall_json": "/home/gavin/git_syscall.json",
         "hash_file": "syscov_git.txt",
         "num_iteration": 5,
         },
    "memcached":
        {"command": "/home/gavin/memcached-1.5.20/memcached -p 11111 -U 11111 -u gavin",
         "server": True,
         "poll": "epoll_wait",
         "clients": [connect_memcached_client],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "memcached_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 5,
         "setup_func": None,
         "poll_time": 3,
         "sc_cov": True,
         "hash_file": "syscov_memcached.txt",
         "cov": False,
         "accept_hash": 3234396722
         },

    "onefile_test":
        {"command": "/home/gavin/onefile",
         "server": False,
         "poll": None,
         "clients": [],
         "sudo": True,
         "retcode": None,
         "env": None,
         "strace_log": "onefile_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 3,
         "poll_time": 3,
         "fuzz_valid": True,
         "a_cov": True,
         "sc_cov": True,
         "syscall_json": "/home/gavin/onefile.json",
         "hash_file": "onefile.txt",
         },
    "docker_test":
        {
        "command": "/onefile",
         "server": False,
         "poll": None,
         "clients": [],
         "sudo": False,
         "retcode": None,
         "env": None,
         "strace_log": "/shared/onefile_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 3,
         "poll_time": 3,
         "fuzz_valid": True,
         "a_cov": True,
         "sc_cov": True,
         "syscall_json": "syscall_g.json",
         "hash_file": "/shared/onefile.txt",
        },
    "git_docker":
        {"command": "/usr/libexec/git-core/git clone root@localhost:/test_repo.git /test_repo",
         "server": False,
         "poll": None,
         "clients": [],
         "sudo": False,
         "retcode": None,
         "env": None,
         "strace_log": "/shared/git_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 15,
         "setup_func": clean_up_git_docker,
         "poll_time": 3,
         "fuzz_valid": True,
         "a_cov": True,
         "sc_cov": True,
         "syscall_json": "/rsyscall_fuzzer/git_syscall.json",
         "hash_file": "/shared/git_hash.txt",
         "value_method": "VALUE_ALL",
         "field_method": "FIELD_ITER",
         "order_method": "ORDER_RECUR",
         "skip_method": "SKIP_ONE",
         },
    "memcahced_docker_test":
        {"command": "/memcached-1.5.20/memcached -p 11111 -U 11111 -u root",
         "server": True,
         "poll": "epoll_wait",
         "clients": [test_memcached_target],
         "sudo": False,
         "retcode": None,
         "env": None,
         "strace_log": "/shared/memcached_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 8,
         "setup_func": None,
         "poll_time": 5,
         "cov": False,
         "a_cov": True,
         "fuzz_valid": True,
         "sc_cov": True,
         "syscall_json": "/rsyscall_fuzzer/memcached_syscall.json",
         "hash_file": "/shared/syscov_memcached.txt",
         "accept_hash": 3758794766,
         "value_method": "VALUE_RANDOM",
         "field_method": "FIELD_ITER",
         "order_method": "ORDER_ALL",
         "skip_method": "SKIP_ONE",
         "field_repeat": 3,
         },

    "lighttpd_docker":
        {"command": "/lighttpd-1.4.51/src/lighttpd "
                    "-D -f /lighttpd.conf",
         "server": True,
         "poll": "epoll_wait",
         "clients": [simple_web_client],
         "sudo": False,
         "retcode": None,
         "env": None,
         "strace_log": "/shared/lighttpd_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 5,
         "setup_func": None,
         "poll_time": 1,
         "cov": False,
         "sc_cov": True,
         "a_cov": True,
         "syscall_json": "/rsyscall_fuzzer/lighttpd_syscall.json",
         "hash_file": "/shared/syscov_lighttpd.txt",
         "fuzz_valid": True,
         "value_method": "VALUE_RANDOM",
         "field_method": "FIELD_ITER",
         "order_method": "ORDER_ALL",
         "skip_method": "SKIP_ONE",
         "field_repeat": 3,
         },
    "openssh_docker":
        {"command": "/openssh/sshd -f /sshd_config -D -d",
         "server": True,
         "poll": "select",
         "clients": [test_openssh_target],
         "sudo": False,
         "retcode": 0,
         "strace_log": "/shared/openssh_strace_log.txt",
         "cwd": None,
         "input": None,
         "timeout": 1,
         "setup_func": None,
         "poll_time": 2,
         "cov": False,
         "sc_cov": True,
         "a_cov": True,
         "syscall_json": "/rsyscall_fuzzer/openssh_syscall.json",
         "hash_file": "/shared/syscov_openssh.txt",
         "fuzz_valid": True,
         "value_method": "VALUE_RANDOM",
         "field_method": "FIELD_ITER",
         "order_method": "ORDER_ALL",
         "skip_method": "SKIP_ONE",
         "field_repeat": 3,
         },
    "zlib_docker":
        {
         "command": "/zlib/example",
         "server": False,
         "poll": None,
         "clients": [],
         "sudo": False,
         "retcode": None,
         "env": None,
         "strace_log": "/shared/zlib_cov_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 3,
         "setup_func": None,
         "poll_time": 3,
         "a_cov": True,
         "sc_cov": True,
         "syscall_json": "/rsyscall_fuzzer/zlib_syscall.json",
         "hash_file": "/shared/syscov_zlib.txt",
         "fuzz_valid": True,
         "value_method": "VALUE_ALL",
         "field_method": "FIELD_ITER",
         "order_method": "ORDER_RECUR",
         "skip_method": "SKIP_ONE",
         "field_repeat": 3,
        },
    "redis_docker":
        {"command": "/redis/src/redis-server --port 6379",
         "server": True,
         "poll": "epoll_wait",
         "clients": [simple_redis_client],
         "sudo": False,
         "retcode": None,
         "env": None,
         "strace_log": "/shared/redis_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 5,
         "setup_func": None,
         "poll_time": 1,
         "cov": False,
         "sc_cov": True,
         "a_cov": True,
         "syscall_json": "/rsyscall_fuzzer/redis_syscall.json",
         "hash_file": "/shared/syscov_redis.txt",
         "fuzz_valid": True,
         "value_method": "VALUE_ALL",
         "field_method": "FIELD_ITER",
         "order_method": "ORDER_RECUR",
         "skip_method": "SKIP_ONE",
         "field_repeat": 3,
         },
    "curl_docker":
        {"command": "/curl/src/curl http://127.0.0.1:8090",
         "server": False,
         "poll": None,
         "clients": [],
         "sudo": False,
         "retcode": None,
         "env": None,
         "strace_log": "/shared/curl_strace.txt",
         "cwd": None,
         "input": None,
         "timeout": 3,
         "setup_func": None,
         "poll_time": 3,
         "fuzz_valid": True,
         "a_cov": True,
         "sc_cov": True,
         "syscall_json": "/rsyscall_fuzzer/curl_syscall.json",
         "hash_file": "/shared/curl_hash.txt",
         "value_method": "VALUE_ALL",
         "field_method": "FIELD_ITER",
         "order_method": "ORDER_RECUR",
         "skip_method": "SKIP_ONE",
         },
}
