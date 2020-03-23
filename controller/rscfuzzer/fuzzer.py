import logging
import sys
import os
import signal
import shlex
import subprocess
import rscfuzzer.const as const
import time
import stat
import hashlib
import shutil
import json
import pickle

from rscfuzzer.target import targets

log = logging.getLogger(__name__)

hash_file_v = "hash_v.txt"
hash_file_f = "hash_f.txt"

class Fuzzer:
    def __init__(self, config, target_name, start_skip=0):
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
        self.strace_log = self.target.get("strace_log", None)
        if self.strace_log is None:
            self.strace_log = self.config.get("strace_log", None)
        if self.strace_log is None:
            sys.exit("no strace log path set")
        try:
            self.strace_log_fd = open(self.strace_log, "w+")
        except IOError as e:
            sys.exit(f"unable to open strace_log file: {self.strace_log}: {e}")
        else:
            log.info(f"strace log will saved to {self.strace_log}")
        try:
            os.chmod(self.strace_log, stat.S_IWOTH | stat.S_IROTH)
        except IOError as e:
            log.info(f"Unable to change permission of strace log file: {self.strace_log}: {e}")

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
        self.store_core_dir = self.config.get("store_core_dir", "stored_cores")
        self.binary = self.command.split(' ')[0].split('/')[-1]
        self.core_dir = os.path.join(self.core_dir, self.binary)

        # mkdir if necessary
        if not os.path.exists(self.core_dir):
            os.makedirs(self.core_dir, mode=0o777)
            os.chmod(self.core_dir, mode=0o777)
        # modify core_dump file
        core_command = f"sudo sysctl -w kernel.core_pattern={os.path.abspath(self.core_dir)}/core.%p"
        args = shlex.split(core_command)
        p = subprocess.Popen(args)
        p.wait()
        log.warn(f"core pattern command to {core_command}")

        self.store_core_dir = os.path.join(self.store_core_dir, self.target_name)

        log.info(f"core dump will be stored in {self.core_dir}, and moved to {self.store_core_dir}")

        # mkdir if necessary
        if not os.path.exists(self.store_core_dir):
            os.makedirs(self.store_core_dir, mode=0o777)
            os.chmod(self.store_core_dir, mode=0o777)

        self.poll_time = self.target.get("poll_time", 3)
        self.gdb_p = None
        self.stack_set = set()

        self.start_skip = start_skip

        self.cov = self.target.get("cov", False)
        self.cov_cwd = self.target.get("cov_cwd", None)
        if self.cov and self.cov_cwd is None:
            sys.exit(f"cov_cwd not set for cov target: {self.target_name}")

        self.sc_cov = self.target.get("sc_cov", False)
        self.hash_file = self.target.get("hash_file", None)
        if self.sc_cov and self.hash_file is None:
            sys.exit(f"hash_file not set for sc_cov target: {self.target_name}")
        self.fuzz_valid = self.target.get("fuzz_valid", False)

        self.vanila_cov = {}
        self.fuzz_cov = {}

        if os.path.isfile(hash_file_v):
            try:
                file = open(hash_file_v, 'rb')
                self.vanila_cov = pickle.load(file)
                file.close()
            except:
                pass

        if os.path.isfile(hash_file_f):
            try:
                file = open(hash_file_f, 'rb')
                self.fuzz_cov = pickle.load(file)
                file.close()
            except:
                pass

        json_dict = {}
        with open(self.syscall_config) as f:
            json_dict = json.load(f)

        syscall_list = json_dict["syscalls"]
        self.supported = []
        for item in syscall_list:
            self.supported.append(item["name"])
        print("supported syscalls: ")
        print(self.supported)

    def setup_env_var(self):
        env_dict = self.target.get("env")
        if env_dict is not None:
            for key, value in env_dict.items():
                self.target_env[key] = value
                log.info(f"env var: {key} -> {value}")

    def clear_cores(self):
        if not os.path.exists(self.core_dir):
            os.makedirs(self.core_dir, mode=0o777)
            os.chmod(self.core_dir, mode=0o777)
        for f in os.listdir(self.core_dir):
            try:
                os.remove(os.path.join(self.core_dir, f))
            except:
                pass

    def clear_hash(self):
        if self.sc_cov:
            try:
                os.remove(self.hash_file)
            except:
                pass

    def parse_hash(self, vanilla=True):
        # hardcode filename
        with open(self.hash_file) as fp:
            lines = fp.readlines()
            dict = self.vanila_cov
            if not vanilla:
                dict = self.fuzz_cov
            for line in lines:
                temp = line.split(': ')
                syscall = temp[0]
                hash = int(temp[1])
                stack = temp[2].replace('%', '\n')
                pair = dict.get(hash)
                if pair is None:
                    if not vanilla:
                        log.info(f'new syscall found: ({hash}, {syscall}): \n {stack}')
                        print(f'new syscall found: ({hash}, {syscall}): \n {stack}')
                        log.info(f'new count: {len(self.fuzz_cov) - len(self.vanila_cov)}/{len(self.vanila_cov)}')
                        print(f'new count: {len(self.fuzz_cov) - len(self.vanila_cov)}/{len(self.vanila_cov)}')
                    dict[hash] = (syscall, 1, stack)
                else:
                    dict[hash] = (syscall, pair[1]+1, stack)
        if vanilla:
            file = open(hash_file_v, 'wb+')
            pickle.dump(dict, file)
            file.close()
        else:
            file = open(hash_file_f, 'wb+')
            pickle.dump(dict, file)
            file.close()

    def clear_cov(self):
        if self.cov:
            clear_cmd = "find . -name '*.gcda' -type f -delete"
            args = shlex.split(clear_cmd)
            p = subprocess.Popen(args, cwd=self.cov_cwd)
            p.wait()

    def store_cov_info(self, name):
        if self.cov:
            store_cmd = f"lcov -c --directory=./ -o {name}.info"
            args = shlex.split(store_cmd)
            p = subprocess.Popen(args, cwd=self.cov_cwd)
            p.wait()
            log.info(f"cov info stored to {name}.info")

    def merge_cov_info(self, name1, name2, output):
        if self.cov:
            store_cmd = f"lcov -a {name1}.info -a {name2}.info -o {output}.info"
            args = shlex.split(store_cmd)
            p = subprocess.Popen(args, cwd=self.cov_cwd)
            p.wait()

    def clear_record(self):
        try:
            os.remove(self.record_file)
        except FileNotFoundError:
            pass

    def clear_strace_log(self):
        self.strace_log_fd.truncate(0)
        self.strace_log_fd.seek(0, 0)

    def kill_servers(self):
        """ kill all running server to avoid port unavaliable """
        if self.srv_p:
            try:
                os.killpg(os.getpgid(self.srv_p.pid), signal.SIGKILL)
            except ProcessLookupError:
                self.srv_p = None

    def kill_gdb(self):
        if self.gdb_p:
            self.gdb_p.kill()

    def handle_core_dump(self):
        core_list = []
        for f in os.listdir(self.core_dir):
            if 'core.' in f:
                core_list.append(os.path.join(self.core_dir, f))
        for file in core_list:
            self.kill_gdb()
            self.gdb_p = subprocess.Popen(
                ["gdb", "-q", self.command.split(' ')[0]],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                close_fds=True,
                env=self.target_env,
            )

            self.gdb_p.stdin.write(("core-file " + file).encode("utf-8") + b"\n")
            self.gdb_p.stdin.flush()

            while True:
                data = self.gdb_p.stdout.readline().decode("utf-8")
                if const.top_stack_pattern.match(data):
                    break
                if const.not_found_pattern.match(data):
                    self.kill_gdb()
                    return

            self.gdb_p.stdin.write("bt".encode("utf-8") + b"\n")
            self.gdb_p.stdin.flush()
            self.gdb_p.stdin.write("p".encode("utf-8") + b"\n")
            self.gdb_p.stdin.flush()

            stack_string = ''
            while True:
                data = self.gdb_p.stdout.readline().decode("utf-8")
                if " at " in data:
                    stack_string += data.split(' at ')[-1]
                if const.empty_history_pattern.match(data):
                    break
            self.kill_gdb()
            # hash the string use sha1 to save memory
            hash_object = hashlib.sha1(stack_string.encode())
            hash_str = hash_object.hexdigest()

            if hash_str not in self.stack_set:
                self.stack_set.add(hash_str)
                log.info(f"new stack found: {stack_string}")
                # store the core with records
                dst = os.path.join(self.store_core_dir, f"core.{hash_str}")
                shutil.copy(file, dst)
                log.info(f"core file stored to {dst}")
                # copy the record file as well
                dst = os.path.join(self.store_core_dir, f"record.{hash_str}.txt")
                shutil.copy(self.record_file, dst)
                log.info(f"record file stored to {dst}")
                # copy strace log as well
                dst = os.path.join(self.store_core_dir, f"strace.{hash_str}.txt")
                shutil.copy(self.strace_log, dst)
                log.info(f"strace file stored to {dst}")

        return len(core_list)

    def run_cov(self):
        log.info(f"running cov test")
        self.clear_cov()
        # run the vanilla version first before poll
        ret = self.run_interceptor_vanilla(True, None)
        ret = self.run_interceptor_vanilla(True, None)
        ret = self.run_interceptor_vanilla(True, None)
        if ret == 0:
            log.info(f"vanilla cov run success, before_poll = true")
        # run the vanilla version with clients if possible
        if self.server:
            if "clients" not in self.target:
                log.error(f"No client defiend for target {self.target_name}")
                return
            # test the part after polling separately for each client
            for client in self.target.get("clients"):
                ret = self.run_interceptor_vanilla(False, client)
                ret = self.run_interceptor_vanilla(False, client)
                ret = self.run_interceptor_vanilla(False, client)
                if ret == 0:
                    log.info(f"vanilla cov run success, before_poll = false")
        # store the cov file for vanilla runs
        self.store_cov_info("vanilla")
        self.clear_cov()

        # run the test
        self.run_interceptor_fuzz(True, None)
        for client in self.target.get("clients"):
            self.run_interceptor_fuzz(False, client)

        # store the cov file for fuzz
        self.store_cov_info("fuzz")
        self.clear_cov()

    def run_sc_cov(self):
        log.info(f"running sc cov test")
        self.clear_hash()
        # run the vanilla version first before poll
        ret = self.run_interceptor_vanilla(True, None)
        self.parse_hash()
        if ret == 0:
            log.info(f"vanilla cov run success, before_poll = true")

        if self.server:
            if "clients" not in self.target:
                log.error(f"No client defiend for target {self.target_name}")
                return
            # test the part after polling separately for each client
            for client in self.target.get("clients"):
                ret = self.run_interceptor_vanilla(False, client)
                self.parse_hash()
                if ret == 0:
                    log.info(f"vanilla cov run success, before_poll = false")

        unsupported_set = set()
        support_count = 0
        ignore_count = 0
        for key, value in self.vanila_cov.items():
            if value[0] in self.supported or value[0] in const.will_do:
                support_count += 1
            elif value[0] in const.ignore_syscall:
                ignore_count += 1
            else:
                unsupported_set.add(value[0])
        log.info(f"support {support_count}/{len(self.vanila_cov)}, "
                 f"{float(support_count)/float(len(self.vanila_cov)) * 100.0}%")
        log.info(f"support remove ignore {support_count}/{len(self.vanila_cov) - ignore_count}, "
                 f"{float(support_count) / float(len(self.vanila_cov) - ignore_count) * 100.0}%")
        log.info(f"usupported set: {unsupported_set}")

        # run the test
        # copy the vanilla_cov to fuzz_cov
        for key, value in self.vanila_cov.items():
            if key not in self.fuzz_cov.keys():
                self.fuzz_cov[key] = value

        self.run_interceptor_fuzz(True, None)
        for client in self.target.get("clients"):
            self.run_interceptor_fuzz(False, client)

        new_count = 0
        for key, value in self.fuzz_cov.items():
            if key not in self.vanila_cov.keys():
                new_count += 1
        log.warning(f"newly added system calls: {new_count}/{len(self.vanila_cov)}, "
                    f"{float(new_count)/float(len(self.vanila_cov)) * 100.0}%")

    def run(self):
        if self.cov:
            self.run_cov()
            return

        if self.sc_cov:
            self.run_sc_cov()
            return

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
        self.run_interceptor_fuzz(before_poll, client)

    def run_interceptor_vanilla(self, before_poll=True, client=None):
        # construct the strace command
        strace_cmd = f"{os.path.join(self.strace_dir, 'strace')} -ff"
        if self.server:
            cur_pid = os.getpid()  # pass pid to the strace, it will send SIGUSR1 back
            strace_cmd = f"{strace_cmd} -j {self.poll} -J {cur_pid}"

        # unnecessary for vanilla run
        # if not before_poll and client is not None:
        #     strace_cmd = f"{strace_cmd} -l"

        if self.sc_cov:
            strace_cmd = f"{strace_cmd} -n {self.hash_file}"

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
            ret = signal.sigtimedwait([const.ACCEPT_SIG], self.poll_time)  # wait until server reach accept
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
                log.info("client success during vanilla run!")
                # check if server terminated
                if self.retcode is not None:
                    # wait for server to terminate
                    try:
                        retcode = self.srv_p.wait(timeout=self.timeout)  # wait for server to terminate after client
                    except (TimeoutError, subprocess.TimeoutExpired):
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
        skip_count = self.start_skip
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

            # add skip count to the command '-G -B', add syscall config, -G means start fuzzing
            strace_cmd = f"{strace_cmd} -G -B {skip_count} -K {os.path.abspath(self.syscall_config)}"

            # add record file if setted
            if self.record_file is not None:
                strace_cmd = f"{strace_cmd} -L {os.path.abspath(self.record_file)}"

            # if test cov -m: only fuzz with valid value -M: cov support, not fuzz cov syscall
            if self.cov:
                strace_cmd = f"{strace_cmd} -M"
            if self.fuzz_valid:
                strace_cmd = f"{strace_cmd} -m"

            if self.sc_cov:
                strace_cmd = f"{strace_cmd} -n {self.hash_file}"

            strace_cmd = f"{strace_cmd} {self.command}"

            if self.sudo:
                strace_cmd = f"sudo -E {strace_cmd}"

            log.info(f"start fuzzing with command {strace_cmd}, "
                     f"num_iterations = {self.iteration}, skip_count={skip_count}")
            args = shlex.split(strace_cmd)
            failed_iters = []

            for i in range(0, self.iteration):
                # run the command multiple times
                # clear core dumps
                self.clear_cores()
                self.clear_record()
                self.clear_strace_log()
                self.clear_hash()
                # make sure no server is running
                self.kill_servers()
                # initialize the retcode with a magic number
                retcode = 10086
                if self.setup_func is not None:
                    self.setup_func()
                log.debug(f"start iteration {i}")
                signal.signal(const.ACCEPT_SIG, signal.SIG_IGN)
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
                        failed_iters.append((i, 'timeout_n'))
                    else:
                        if self.retcode != retcode:
                            self.kill_servers()
                            # return code do not match
                            failed_iters.append((i, retcode))
                            should_increase = True
                else:  # handle servers
                    # check if server exist before wait for signal (save time)
                    time.sleep(0.5)
                    retcode = self.srv_p.poll()
                    log.debug("check server exist before wait for signal")
                    if retcode is not None:
                        failed_iters.append((i, retcode))
                        should_increase = True
                    else:
                        # ignore signal
                        # Wait for sigmax-7, or acknowledge if it is already pending
                        log.debug("wait for server's signal ...")
                        ret = signal.sigtimedwait([const.ACCEPT_SIG], self.poll_time)  # wait until server reach accept
                        signal.pthread_sigmask(signal.SIG_UNBLOCK, [const.ACCEPT_SIG])
                        if ret is None:  # timeout
                            log.debug("signal timeout!")
                            failed_iters.append((i, 'timeout_p'))
                            should_increase = True
                            # check server state
                            retcode = self.srv_p.poll()
                            if retcode is not None:
                                failed_iters.append((i, retcode))
                            self.kill_servers()
                        else:
                            log.debug("signal received!")
                            # check if this turn only test before poll:
                            if before_poll:
                                # check if the server crashes,
                                ret = self.srv_p.poll()
                                if ret is None:  # terminate the server and return
                                    os.killpg(os.getpgid(self.srv_p.pid), signal.SIGTERM)
                                    log.debug("terminate the server, wait until it terminate..")
                                    self.srv_p.wait()  # wait until strace properly save the output
                                    log.debug("server terminated")
                                # server terminate before client, report error
                                else:
                                    self.kill_servers()
                                    failed_iters.append((i, 'exit_b'))
                                    should_increase = True
                            else:  # after polling, connect a client
                                time.sleep(const.CLIENT_DELAY)
                                log.debug("connecting client ...")
                                client_ret = client()
                                log.debug(f"client ret code {client_ret}")
                                if client_ret != 0:
                                    log.debug(f"client failed, kill server, wait ... ")
                                    os.killpg(os.getpgid(self.srv_p.pid), signal.SIGTERM)
                                    self.srv_p.wait()  # wait until strace properly save the output
                                    log.debug(f"server terminated ... ")
                                    failed_iters.append((i, 'client_f'))
                                    should_increase = True
                                else:  # client success, check state of server
                                    try:  # wait for server to terminate after client
                                        retcode = self.srv_p.wait(timeout=self.timeout)
                                    except (TimeoutError, subprocess.TimeoutExpired):
                                        log.debug("server still exist after client, try to terminate it ...")
                                        os.killpg(os.getpgid(self.srv_p.pid), signal.SIGTERM)
                                        self.srv_p.wait()  # wait until cov properly save the output
                                        log.debug("server terminated!")
                                        if self.retcode is not None:  # should exit
                                            failed_iters.append((i, 'timeout_a'))
                                            should_increase = True
                                    else:
                                        if retcode != self.retcode:  # check if retcode match
                                            self.kill_servers()
                                            failed_iters.append((i, retcode))
                                            should_increase = True

                # handle core dumped
                core_ret = self.handle_core_dump()
                if core_ret > 0:
                    self.kill_servers()
                    failed_iters.append((i, 'core'))
                    should_increase = True
                # for iteration, code in failed_iters:
                #     if iteration == i:
                #         log.info(f"{iteration}: {code}")
                self.parse_hash(False)

            # output list if necessary
            log.info(failed_iters)
            if should_increase:
                skip_count = skip_count+1
