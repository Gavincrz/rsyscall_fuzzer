import logging
import sys
import os
import signal
import shlex
import subprocess
import rscfuzzer.const as const
import time
import stat
import pwd
import grp
from rscfuzzer.target import targets

log = logging.getLogger(__name__)


class Fuzzer:
    def __init__(self, config, target_name):
        self.config = config

        # check if it is a valid target
        if target_name not in targets:
            sys.exit(f"{target_name} is not a valid target, "
                     f"you could add the target into target.py")

        self.target_name = target_name
        self.target = targets[target_name]

        # check if strace dir is set
        if "strace_dir" not in config:
            sys.exit(f"strace_dir is not set in config")
        self.strace_dir = config["strace_dir"]

        self.server = self.target.get("server", False)
        # get the polling syscall for server
        if self.server:
            log.info(f"target {target_name} is a server, looking for polling syscall...")
            self.poll = self.target.get("poll")
            if self.poll is None:
                sys.exit("no polling syscall set for the server target")
            log.info(f"polling syscall: {self.poll}")

        # check if target need sudo
        self.sudo = self.target.get("sudo", False)

        # check if target have normal return code
        self.retcode = self.target.get("retcode", None)

        # initialize server process
        self.srv_p = None

        # setup environment variable
        self.target_env = os.environ.copy()
        self.setup_env_var()

        # check strace log file, target config has high priority
        strace_log = self.target.get("strace_log", None)
        if strace_log is None:
            strace_log = self.config.get("strace_log", None)
        if strace_log is None:
            sys.exit("no strace log path set")
        try:
            self.strace_log_fd = open(strace_log, "w+")
        except IOError as e:
            sys.exit(f"unable to open strace_log file: {strace_log}: {e}")
        else:
            log.info(f"strace log will saved to {strace_log}")
        try:
            os.chmod(strace_log, stat.S_IWOTH | stat.S_IROTH)
        except IOError as e:
            log.info(f"Unable to change permission of strace log file: {strace_log}: {e}")

        # check if target need to be run in specific directory
        self.target_cwd = self.target.get("cwd", None)

        # check if non-server application need input TODO: need to handle case where server need stdin
        self.input = self.target.get("input", None)

        # get process timeout, for non-server application
        self.timeout = self.target.get("timeout", 3)

        # get target command
        self.command = self.target.get("command", None)
        if self.command is None:
            sys.exit(f"command not set for target: {self.target_name}")

        self.syscall_config = self.config.get("syscall_config", None)
        if self.syscall_config is None:
            sys.exit("syscall config file not provided")

        self.record_file = self.config.get("record_file", None)

        self.iteration = self.config.get("num_iteration", 20)

        self.setup_func = self.target.get("setup_func", None)

        self.core_dir = self.config.get("core_dir", "cores")
        self.binary = self.command.split("/")[-1]
        self.core_dir = os.path.join(self.core_dir, self.binary)
        log.info(f"core dump will be stored in {self.core_dir}")

    def setup_env_var(self):
        env_dict = self.target.get("env")
        for key, value in env_dict.items():
            self.target_env[key] = value
            log.debug(f"env var: {key} -> {value}")

    def clear_cores(self):
        for f in os.listdir(self.core_dir):
            os.remove(os.path.join(self.core_dir, f))

    def kill_servers(self):
        """ kill all running server to avoid port unavaliable """
        if self.srv_p:
            try:
                os.killpg(os.getpgid(self.srv_p.pid), signal.SIGKILL)
            except ProcessLookupError:
                self.srv_p = None

    def run(self):
        # test the application or part before polling in a server
        self.test_target(True)

        # if target is a server, also fuzz the second part
        if self.server:
            if "clients" not in self.target:
                log.error(f"No client defiend for target {self.target_name}")
                return
            # test the part after polling separately for each client
            for client in self.target.get("clients"):
                self.test_target(False, client)

    def test_target(self, before_poll=True, client=None):
        # run the vanilla version first
        ret = self.run_interceptor_vanilla(before_poll, client)
        if ret == 0:
            log.info(f"vanilla run success, before_poll = {before_poll}")
        # run the test version
        # self.run_interceptor_fuzz(before_poll, client)

    def run_interceptor_vanilla(self, before_poll=True, client=None):
        # construct the strace command
        strace_cmd = f"{os.path.join(self.strace_dir, 'strace')} -ff"
        if self.server:
            cur_pid = os.getpid()  # pass pid to the strace, it will send SIGUSR1 back
            strace_cmd = f"{strace_cmd} -j {self.poll} -J {cur_pid}"

        # unnecessary for vanilla run
        # if not before_poll and client is not None:
        #     strace_cmd = f"{strace_cmd} -l"

        strace_cmd = f"{strace_cmd} {self.command}"

        if self.sudo:
            strace_cmd = f"sudo -E {strace_cmd}"

        # run the interceptor, make sure nothing else is running
        self.kill_servers()
        log.info(f"running vanilla target with command {strace_cmd}")
        args = shlex.split(strace_cmd)
        # Block signal until sigwait (if caught, it will become pending)
        signal.pthread_sigmask(signal.SIG_BLOCK, [const.ACCEPT_SIG])

        self.srv_p = subprocess.Popen(args,
                                      stdin=subprocess.PIPE,
                                      stdout=self.strace_log_fd,
                                      stderr=self.strace_log_fd,
                                      preexec_fn=os.setsid,
                                      cwd=self.target_cwd,
                                      env=self.target_env)

        # wait for accept signal if it is a server
        if self.server:
            # ignore signal
            signal.signal(const.ACCEPT_SIG, signal.SIG_IGN)
            # Wait for sigmax-7, or acknowledge if it is already pending
            ret = signal.sigtimedwait([const.ACCEPT_SIG], 2)  # wait until server reach accept
            signal.pthread_sigmask(signal.SIG_UNBLOCK, [const.ACCEPT_SIG])
            if ret:
                logging.debug(f"sig {const.ACCEPT_SIG} received!")
            else:
                self.kill_servers()
                sys.exit("signal wait timeout during vanilla run, terminate the process")

            # check if this turn only test before poll:
            if before_poll:
                # check if the server crashes,
                ret = self.srv_p.poll()
                if ret is None: # terminate the server and return
                    os.killpg(os.getpgid(self.srv_p.pid), signal.SIGTERM)
                    self.srv_p.wait()  # wait until strace properly save the output
                    log.info("vanilla test before polling success")
                    return 0
                # server terminate before client, report error
                else:
                    self.kill_servers()
                    sys.exit(f"server terminate before client, retcode = {ret}")

            # after polling for server
            if client is None:
                self.kill_servers()
                sys.exit("error: client not set when test after polling")
            time.sleep(const.CLIENT_DELAY)
            client_ret = client()
            if client_ret != 0:
                self.kill_servers()
                sys.exit("error: client failed during vanilla run!")
            else:
                log.debug("client success during vanilla run!")
                # check if server terminated
                if self.retcode is not None:
                    # wait for server to terminate
                    try:
                        retcode = self.srv_p.wait(timeout=self.timeout)  # wait for server to terminate after client
                    except TimeoutError:
                        self.kill_servers()
                        sys.exit("server timeout after client (should terminate), kill the server")
                    else:
                        if self.retcode != retcode:
                            self.kill_servers()
                            sys.exit(f"server terminate after client, expect retcode:{self.retcode}, actual: {retcode}")
                        else:
                            return 0
                retcode = self.srv_p.poll()
                if retcode is None:
                    os.killpg(os.getpgid(self.srv_p.pid), signal.SIGTERM)
                    self.srv_p.wait()  # wait until strace properly save the output
                    log.info(f"server still running after client, terminate the server")

        # for non-server target
        else:
            if self.input:
                self.srv_p.communicate(self.input.encode("utf-8").decode('unicode_escape').encode("utf-8"))
            try:
                retcode = self.srv_p.wait(self.timeout)  # wait for 2 second, if not ret, something happened
            except subprocess.TimeoutExpired:
                # timeout, kill the program and do nothing
                self.kill_servers()
                sys.exit(f"application timeout")
            else:
                if self.retcode is None:  # set the normal retcode to retcode
                    self.retcode = retcode
                    log.info(f"normal retcode set to {retcode} for the non-server target")
                elif self.retcode != retcode:
                    self.kill_servers()
                    sys.exit(f"application terminate with error in vanilla run, "
                             f"expect retcode:{self.retcode}, actual: {retcode}")
        return 0

    def run_interceptor_fuzz(self, before_poll=True, client=None):
        skip_count = 0
        should_increase = True
        while should_increase: # fuzzing loop, end until application terminate properly
            should_increase = False
            # construct strace command
            strace_cmd = f"{os.path.join(self.strace_dir, 'strace')} -ff"
            if self.server:
                cur_pid = os.getpid()  # pass pid to the strace, it will send SIGUSR1 back
                strace_cmd = f"{strace_cmd} -j {self.poll} -J {cur_pid}"
            if not before_poll and client is not None:
                strace_cmd = f"{strace_cmd} -l"

            # add skip count to the command '-B', add syscall config
            strace_cmd = f"{strace_cmd} -B {skip_count} -K {os.path.abspath(self.syscall_config)}"

            # add record file if setted
            if self.record_file is not None:
                strace_cmd = f"{strace_cmd} -L {os.path.abspath(self.record_file)}"

            strace_cmd = f"{strace_cmd} {self.command}"

            if self.sudo:
                strace_cmd = f"sudo -E {strace_cmd}"

            log.info(f"start fuzzing with command {strace_cmd}, num_iterations = {self.iteration}")
            args = shlex.split(strace_cmd)
            failed_iters = []

            for i in range(0, self.iteration):
                # run the command multiple times

                # clear core dumps
                self.clear_cores()
                # make sure no server is running
                self.kill_servers()
                if self.setup_func is not None:
                    self.setup_func()

                # Block signal until sigwait (if caught, it will become pending)
                signal.pthread_sigmask(signal.SIG_BLOCK, [const.ACCEPT_SIG])

                self.srv_p = subprocess.Popen(args,
                                              stdin=subprocess.PIPE,
                                              stdout=self.strace_log_fd,
                                              stderr=self.strace_log_fd,
                                              preexec_fn=os.setsid,
                                              cwd=self.target_cwd,
                                              env=self.target_env)
                if not self.server:
                    if self.input:
                        self.srv_p.communicate(self.input.encode("utf-8").decode('unicode_escape').encode("utf-8"))
                    try:
                        retcode = self.srv_p.wait(self.timeout)  # wait for 2 second, if not ret, something happened
                    except subprocess.TimeoutExpired:
                        # timeout, kill the program and record failure
                        self.kill_servers()
                        should_increase = True
                        failed_iters.append((i, 'Timeout'))
                    else:
                        if self.retcode != retcode:
                            self.kill_servers()
                            # return code do not match
                            failed_iters.append((i, retcode))
                            should_increase = True
                else:  # handle servers
                    pass

                # handle core dumped
