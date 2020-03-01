import paramiko
import logging
import warnings

# suppress warning and logs for paramiko
warnings.filterwarnings(action='ignore',module='.*paramiko.*')
logging.getLogger("paramiko").setLevel(logging.WARNING)

log = logging.getLogger(__name__)


# client functions
def openssh_simple_client():
    try:
        ssh = paramiko.SSHClient()
        ssh.load_host_keys("/home/gavin/.ssh/known_hosts")
        ssh.connect("localhost", port=8080, username="gavin")
        ssh.exec_command("exit")
        ssh.close()
    except Exception as err:
        log.error(f"{err}")
        return -1
    else:
        return 0


targets = {
    "openssh": {"command": "/home/gavin/openssh/sshd -f /home/gavin/ssh_trace/sshd_config -D -d",
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
                }
}