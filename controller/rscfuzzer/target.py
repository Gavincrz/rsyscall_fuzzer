import paramiko
import logging

log = logging.getLogger(__name__)

targets = {
    "openssh": {"command": "/home/gavin/openssh/sshd -f /home/gavin/ssh_trace/sshd_config -D -d",
                "server": True,
                "poll": "select",
                "clients": [],
                }
}


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
