import paramiko
import logging
import warnings
import urllib.request as request

# suppress warning and logs for paramiko
warnings.filterwarnings(action='ignore',module='.*paramiko.*')
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

log = logging.getLogger(__name__)


# client functions
def openssh_simple_client():
    try:
        ssh = paramiko.SSHClient()
        ssh.load_host_keys("/home/gavin/.ssh/known_hosts")
        ssh.connect("localhost", port=8080, username="gavin", timeout=5)
        ssh.exec_command("exit")
        ssh.close()
    except Exception as err:
        # log.error(f"{err}")
        return -1  
    else:
        return 0


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
         "cov": False
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
         "cov": False
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
         "cov": True,
         "cov_cwd": "/home/gavin/lighttpd-cov/",
         "fuzz_valid": False,
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
         "fuzz_valid": False,
         },
}