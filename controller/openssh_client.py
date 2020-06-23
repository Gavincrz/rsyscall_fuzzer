#!/usr/bin/env python3
import paramiko
import logging
import warnings
# suppress warning and logs for paramiko
warnings.filterwarnings(action='ignore',module='.*paramiko.*')
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
ssh = None
try:
    try:
        ssh = paramiko.SSHClient()
        ssh.load_host_keys("/root/.ssh/known_hosts")
        ssh.connect("localhost", port=8080, username="root", timeout=1, banner_timeout=1, auth_timeout=1)
        # stdin, stdout, stderr = ssh.exec_command("ls -l / \n", timeout=5)
        # output = stdout.read()
        # print(output)
        retcode = 0
    except Exception as err:
        # print(f"{err}")
        retcode = -1
    else:
        retcode = 0
    finally:
        if ssh is not None:
            try:
                ssh.close()
            except Exception as err:
                retcode = -1
except Exception as err:
    retcode = -1
exit(retcode)
