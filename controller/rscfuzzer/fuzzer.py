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
import psutil
import random
import copy
import resource
import mmh3
import magic
import re
import string
from enum import Enum
from rscfuzzer.target import targets

log = logging.getLogger(__name__)

hash_file_v = "hash_v.txt"
hash_file_f = "hash_f.txt"
coverage_file = "coverage.txt"

ld_cmd = "LD_LIBRARY_PATH=/home/gavin/libunwind/build/usr/local/lib"


class ValueMethod(Enum):
    VALUE_ALL = 0
    VALUE_RANDOM = 1
    VALUE_INVALID = 2


class FieldMethod(Enum):
    FIELD_ITER = 0
    FIELD_RANDOM = 1
    FIELD_ALL = 2


class OrderMethod(Enum):
    ORDER_RECUR = 0
    ORDER_SEP = 1
    ORDER_ALL = 2

class SkipMethod(Enum):
    SKIP_FAIL = 0
    SKIP_ONE = 1

class FuzzResult(Enum):
    FUZZ_SUCCESS = 0
    FUZZ_SIGTIMEOUT = 1
    FUZZ_ERROR = 2
    FUZZ_EXECTIMEOUT = 3
    FUZZ_RETNOTMATCH = 4
    FUZZ_EXITB4POLL = 5
    FUZZ_COREDUMP = 6
    FUZZ_EXITB4CLIENT = 7
    FUZZ_CLIENTFAIL = 8


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
        self.cache_unwind = True

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
            log.error(f"strace log will saved to {self.strace_log}")
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
        self.count_file = self.config.get("count_file", "count.txt")

        self.iteration = self.config.get("num_iteration", 20)
        target_iteration = self.target.get("num_iteration", None)
        if target_iteration is not None:
            self.iteration = target_iteration
        log.warning(f'number of iteration for each skip count set to {self.iteration}')
        self.setup_func = self.target.get("setup_func", None)

        self.core_dir = self.config.get("core_dir", "cores")
        self.store_core_dir = self.config.get("store_core_dir", "stored_cores")
        self.binary = self.command.split(' ')[0].split('/')[-1]
        self.executable = os.path.abspath(self.command.split(' ')[0])
        print(f"executable abs path is {self.executable}")
        self.core_dir = '/shared/cores/'
        signal.signal(const.ACCEPT_SIG, signal.SIG_IGN)
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
        if self.hash_file is not None and self.target_cwd is not None:
            self.hash_file = os.path.join(self.target_cwd, self.hash_file)
        print(f'hash_file = {self.hash_file}')

        self.a_cov = self.target.get('a_cov', False)
        self.sysjson = self.target.get('syscall_json', None)
        if self.a_cov and (self.hash_file is None or self.sysjson is None):
            sys.exit(f"both sysjson and hash_file need to be set for r_cov")
        if self.a_cov:
            self.syscall_config = self.sysjson

        # always use auto generated syscall_json file if provided
        if self.sysjson is not None:
            self.syscall_config = self.sysjson

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

        mismatch_syscalls = []

        syscall_list = json_dict["syscalls"]
        self.supported = []
        for item in syscall_list:
            if item["name"] in const.syscall_field_index.keys():
                self.supported.append(item["name"])
            else:
                mismatch_syscalls.append(item["name"])
        if len(mismatch_syscalls) > 0:
            print("there are some syscalls in value dict but not in index dict!")
            print(mismatch_syscalls)

        print("supported syscalls: ")
        print(self.supported)

        self.value_dict = {}
        # rearrange the json dict in a friendly way
        for item in syscall_list:
            append_dict = {}
            syscall_name = item["name"]
            for key,value in item.items():
                if key != "name":
                    append_dict[key] = value
            # add append_dict to value_dict
            self.value_dict[syscall_name] = append_dict
        print(self.value_dict)

        # measurement option:
        self.measurement = False
        self.not_write = False
        self.print_trace = False
        self.accept_time = 0
        self.client_time = 0
        self.after_time = 0

        self.accept_hash = self.target.get("accept_hash", -1)

        # list that contains vanilla syscall list, only contain supported
        self.vanilla_syscall_dict = {}
        self.overall_set = set()

        # coverage contain all the invocations's hash key = syscall+hash
        self.coverage_dict = {}

        # load coverage file if exist
        if os.path.isfile(coverage_file):
            try:
                file = open(coverage_file, 'rb')
                self.coverage_dict = pickle.load(file)
                file.close()
            except:
                pass
        # load overallset
        for key in self.coverage_dict.keys():
            split_list = key.split('@')
            syscall = split_list[0]
            if syscall in self.value_dict.keys():
                self.overall_set.add(key)

        print(f"size of loaded coverage is {len(self.coverage_dict)}, size of loaded overalset is {len(self.overall_set)}")

        # syscall_set contain all syscalls in the application
        self.unsupported_syscalls = set()
        self.vanilla_list = None
        # print unsupported syscalls
        self.get_unsupported_syscalls()
        self.max_depth = self.config.get('max_depth', 50)
        self.reference_file = os.path.abspath(self.config.get('reference_file', "reference.txt"))

        proc = psutil.Process()
        log.warning(f'opened files: {proc.open_files()}')

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        log.warning(f'soft = {soft}, hard = {hard}')
        resource.setrlimit(resource.RLIMIT_NOFILE, (1048576, 1048576))
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        log.warning(f'after set: soft = {soft}, hard = {hard}')

        # get method to update value index
        value_method_name = self.target.get("value_method", "VALUE_ALL")
        if value_method_name not in ValueMethod.__members__:
            log.error(f'{value_method_name} is not a valid value method')
            self.value_method = ValueMethod.VALUE_ALL
        else:
            self.value_method = ValueMethod[value_method_name]
        log.warning(f'value method set to {self.value_method}')

        # get method to update field index
        field_method_name = self.target.get("field_method", "FIELD_ITER")
        if field_method_name not in FieldMethod.__members__:
            log.error(f'{field_method_name} is not a valid field method')
            self.field_method = FieldMethod.FIELD_ITER
        else:
            self.field_method = FieldMethod[field_method_name]
            if self.field_method != FieldMethod.FIELD_ITER:
                self.value_method = ValueMethod.VALUE_RANDOM
                log.warning(f'value method reset to {self.value_method} because of field method')
        log.warning(f'field method set to {self.field_method}')

        order_method_name = self.target.get("order_method", "ORDER_RECUR")
        if order_method_name not in OrderMethod.__members__:
            log.error(f'{order_method_name} is not a valid order method')
            self.order_method = OrderMethod.ORDER_RECUR
        else:
            self.order_method = OrderMethod[order_method_name]
        log.warning(f'order method set to {self.order_method}')


        skip_method_name = self.target.get("skip_method", "SKIP_FAIL")
        if skip_method_name not in SkipMethod.__members__:
            log.error(f'{skip_method_name} is not a valid skip method')
            self.skip_method = SkipMethod.SKIP_FAIL
        else:
            self.skip_method = SkipMethod[skip_method_name]
        log.warning(f'skip method set to {self.skip_method}')

        # make a dir for storing random files
        self.random_dir = self.config.get("random_dir", "/random")
        # mkdir random dir necessary
        if not os.path.exists(self.random_dir):
            os.makedirs(self.random_dir, mode=0o666)
            os.chmod(self.random_dir, mode=0o666)

        self.clear_random_files()

        # make a dir for storing error strace files
        self.errorlog_dir = self.config.get("error_dir", "/errorlog")
        # mkdir random dir necessary
        if not os.path.exists(self.errorlog_dir):
            os.makedirs(self.errorlog_dir, mode=0o666)
            os.chmod(self.errorlog_dir, mode=0o666)
        self.errorcount = 0
        # a set to record fuzzed syscalls
        self.fuzzed_set = set()

    def clear_time_measurement(self):
        self.accept_time = 0
        self.client_time = 0
        self.after_time = 0

    def setup_env_var(self):
        # add libunwind library to LD_LIBRARY_PATH
        self.target_env['LD_LIBRARY_PATH'] = '/home/gavin/libunwind/build/usr/local/lib'
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

    def clear_random_files(self):
        for f in os.listdir(self.random_dir):
            try:
                os.remove(os.path.join(self.random_dir, f))
            except:
                pass

    def clear_hash(self):
        if self.sc_cov:
            try:
                os.remove(self.hash_file)
            except:
                pass

    def run_hundred_measurement(self, before_poll, client, indicator):
        self.clear_time_measurement()
        start = time.time()
        for i in range(100):
            self.run_interceptor_vanilla(before_poll, client)
            print(self.retcode, end='', flush=True)
        end = time.time()

        print(f'\nrun time of vanilla {indicator}: {end - start}, after time: {self.after_time}, '
              f'acccept_time: {self.accept_time}')

    def run_measurement(self):
        # run the vanilla version first
        self.sc_cov = False
        if not self.server:
            start = time.time()
            for i in range(100):
                self.run_interceptor_vanilla(True, None, True)
                print(self.retcode, end='', flush=True)
            end = time.time()
            print(f'run time of origin: {end - start} ')

        self.run_hundred_measurement(True, None, "no client strace")

        self.sc_cov = True
        self.not_write = True
        self.cache_unwind = False
        self.run_hundred_measurement(True, None, "no client trace stack (ori_unwind)")

        self.sc_cov = True
        self.not_write = True
        self.cache_unwind = True
        self.run_hundred_measurement(True, None, "no client record stack (cache unwind)")

        self.print_trace = False
        if self.server:
            if self.accept_hash == -1:
                # test with client
                self.sc_cov = False
                self.run_hundred_measurement(False, self.target.get("clients")[0], "vanilla client")

            self.sc_cov = True
            self.not_write = True
            self.cache_unwind = False
            self.run_hundred_measurement(False, self.target.get("clients")[0], "client trace stack(ori_unwind)")

            self.sc_cov = True
            self.not_write = True
            self.print_trace = False
            self.cache_unwind = True
            self.run_hundred_measurement(False, self.target.get("clients")[0], "client record stack(cache_unwind)")

    def parse_syscall_order(self, before=True):
        syscall_order = []
        poll_found = False
        # find continous poll syscall
        poll_start = False
        poll_count = 0
        with open(self.hash_file) as fp:
            lines = fp.readlines()
            for line in lines:
                syscall, hash, stack = self.parse_syscall_stack(line)
                if before:
                    syscall_order.append((syscall, hash, stack))
                else:
                    # only add syscall after poll found
                    if not poll_found:
                        if syscall == self.poll:
                            poll_found = True
                            poll_start = True
                            poll_count = 1
                            syscall_order.append((syscall, hash, stack))
                    else:
                        if poll_start:
                            # neglect multiple poll syscall
                            if syscall != self.poll:
                                poll_count += 1
                            else:
                                poll_start = False
                                syscall_order.append((syscall, hash, stack))
                        else:
                            syscall_order.append((syscall, hash, stack))


        return syscall_order

    def parse_syscall_stack_string_hash(self, line):
        temp = line.split(': ')
        syscall = temp[0]
        hash_str = temp[1]
        stack = temp[2].replace('%', '\n')
        return syscall, hash_str, stack

    def parse_syscall_stack(self, line):
        temp = line.split(': ')
        syscall = temp[0]
        hash_val = int(temp[1])
        stack = temp[2].replace('%', '\n')
        return syscall, hash_val, stack

    def run_magic_test(self):
        self.clear_hash()
        # run the vanilla version first before poll
        ret = self.run_interceptor_vanilla(True, None)
        self.parse_supported_hash("before.txt")
        if ret == 0:
            log.info(f"vanilla cov run success, before_poll = true")

        if self.server:
            if "clients" not in self.target:
                log.error(f"No client defiend for target {self.target_name}")
                return
            # test the part after polling separately for each client
            for client in self.target.get("clients"):
                ret = self.run_interceptor_vanilla(False, client)
                self.parse_supported_hash("after.txt")
                if ret == 0:
                    log.info(f"vanilla cov run success, before_poll = false")

    def store_syscall_coverage(self):
        file = open(coverage_file, 'wb+')
        pickle.dump(self.coverage_dict, file)
        file.close()

    def parse_supported_hash(self, target_syscall=None, target_hash=None, vanilla=False):
        # return supported newly found syscall invocation, use dictionary to preserve order
        support_new_syscall_dict = {}
        unsupported_dict = {}
        has_target = target_syscall is not None and target_hash is not None
        # if not has target, always update overall set, for vanilla set
        target_found = not has_target

        if not os.path.isfile(self.hash_file):
            log.error(f"{self.hash_file} does not exist after server")
            return None
        
        with open(self.hash_file) as fp:
            lines = fp.readlines()
            for line in lines:
                syscall, hash_str, stack = self.parse_syscall_stack_string_hash(line)
                # check if syscall already encountered in overallstack
                str_key = f'{syscall}@{hash_str}'
                if syscall in self.supported:
                    # check if syscall match target
                    if has_target and syscall == target_syscall and hash_str == target_hash:
                        target_found = True
                    # if not, add to new stack
                    if not str_key in self.overall_set or vanilla:
                        support_new_syscall_dict[str_key] = stack
                elif str_key not in self.coverage_dict.keys():
                    unsupported_dict[str_key] = stack
                # always record coverage
                self.coverage_dict[str_key] = stack

            # if target syscall found otherwise return null
            if target_found:
                log.debug(f'{len(unsupported_dict)} new unsupported invokation found')
                return support_new_syscall_dict
            else:
                return None

    def parse_hash(self, vanilla=True):
        # hardcode filename
        with open(self.hash_file) as fp:
            lines = fp.readlines()
            dict = self.vanila_cov
            if not vanilla:
                dict = self.fuzz_cov
            for line in lines:
                syscall, hash, stack = self.parse_syscall_stack(line)
                pair = dict.get(hash)
                if pair is None:
                    # if not vanilla:
                        # log.info(f'new syscall found: ({hash}, {syscall}): \n {stack}')
                        # print(f'new syscall found: ({hash}, {syscall}): \n {stack}')
                        # log.info(f'new count: {len(self.fuzz_cov) - len(self.vanila_cov)}/{len(self.vanila_cov)}')
                        # print(f'new count: {len(self.fuzz_cov) - len(self.vanila_cov)}/{len(self.vanila_cov)}')
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
                os.kill(self.srv_p.pid, signal.SIGTERM)
            except ProcessLookupError:
                self.srv_p.kill()

            # wait for fewer seconds to terminate
            try:
                self.srv_p.wait(10)  # wait until cov properly save the output
            except:
                log.error("server terminate time out, force kill")

            try:
                os.killpg(os.getpgid(self.srv_p.pid), signal.SIGKILL)
            except ProcessLookupError:
                self.srv_p.kill()
                self.srv_p = None
        for proc in psutil.process_iter():
            # check whether the process name matches
            try:
                if self.executable in proc.exe():
                    print(f"found not killed process, kill it {self.executable}")
                    proc.kill()
            except:
                continue
        if self.srv_p is not None:
            self.srv_p.kill()

    def kill_gdb(self):
        if self.gdb_p:
            self.gdb_p.kill()

    def handle_core_dump_script(self, retcode=None, targets=None, skip_count=-1):
        core_list = []
        # get all core dumps in the core_dir
        for f in os.listdir(self.core_dir):
            if 'core.' in f:
                core_list.append(os.path.join(self.core_dir, f))
        for file in core_list:
            # get the type of core dump and
            try:
                type_info = magic.from_file(file)
            except Exception as e:
                log.error(f'error read file type: {e}')
                continue
            m = re.search(r"execfn: \'(\S+)\'", type_info)
            if m is None:
                # not a recognized core dump file
                log.error(f'core file not recoginized: {file}, type info: {type_info}, target = {targets}')
                dst = os.path.join(self.store_core_dir, f"core.empty")
                shutil.copy(file, dst)
                dst = os.path.join(self.store_core_dir, f"strace.empty.txt")
                shutil.copy(self.strace_log, dst)
                core_exec = self.executable
            else:
                # check if exec matches
                core_exec = m.group(1)
            if core_exec != self.executable:
                log.error(f'core file does not belong to target binary: {core_exec}, target = {targets}')
            # run gdb to get stack string using python script
            # make sure previous gdb session is killed
            # remove temp file if exist
            if os.path.exists(const.gdb_temp_file):
                os.remove(const.gdb_temp_file)

            core_binary = core_exec.split('/')[-1]

            self.kill_gdb()
            args_gdb = shlex.split(f'gdb {core_exec} {file} -q -x {const.gdb_script}')
            try:
                subprocess.run(args_gdb, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.TimeoutExpired as TE:
                log.error(f'gdb subprocess timeout {TE}')
                continue
            except Exception as e:
                log.error(f'gdb subprocess error: {e}')
                continue
            # parsing the output:
            data = ''
            if not os.path.isfile(const.gdb_temp_file):
                log.error('gdb temp file read failed')
                continue
            with open(const.gdb_temp_file, 'r') as output_f:
                data = output_f.read()
            if len(data) <= 0:
                log.error('gdb temp file read failed')
                continue
            # data should not contain error message:
            if "gdb script error:" in data:
                log.error(data)
                continue
            hash = mmh3.hash64(data, signed=False)[0]
            if hash not in self.stack_set:
                self.stack_set.add(hash)
                log.info(f"new stack found:\n{data}")
                log.debug(f'original core file = {file}')
                hash_str = f'{hash}.{retcode}.{core_binary}'
                # store the core with records
                dst = os.path.join(self.store_core_dir, f"core.{hash_str}")
                shutil.copy(file, dst)
                log.info(f"core file stored to {dst}")
                log.error(f"New Core Found: stored to {dst}, retcode=[{retcode}], targets=[{targets}], skip_count=[{skip_count}]")
                # copy the record file as well
                dst = os.path.join(self.store_core_dir, f"record.{hash_str}.txt")
                shutil.copy(self.record_file, dst)
                log.info(f"record file stored to {dst}")
                # copy strace log as well
                dst = os.path.join(self.store_core_dir, f"strace.{hash_str}.txt")
                shutil.copy(self.strace_log, dst)
                log.info(f"strace file stored to {dst}")
                log.info("finish handle core dump")
        return len(core_list)

    def handle_core_dump(self, retcode=None, targets=None, skip_count=-1):
        core_list = []
        # log.info("handle core dump")
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

            pattern_not_found = False
            data = ''
            while True:
                data = self.gdb_p.stdout.readline().decode("utf-8")
                if const.top_stack_pattern.match(data):
                    break
                if const.not_found_pattern.match(data) or const.gdb_not_found.match(data):
                    self.kill_gdb()
                    pattern_not_found = True
                    break

            if pattern_not_found:
                log.error(f"core anlyze failed: {data}, parh: {file}")
                continue

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
                hash_str = f'{hash_str}.{retcode}'
                # store the core with records
                dst = os.path.join(self.store_core_dir, f"core.{hash_str}")
                shutil.copy(file, dst)
                log.info(f"core file stored to {dst}")
                log.error(f"New Core Found: stored to {dst}, retcode=[{retcode}], "
                          f"targets=[{targets}], skip_count=[{skip_count}]")
                # copy the record file as well
                dst = os.path.join(self.store_core_dir, f"record.{hash_str}.txt")
                shutil.copy(self.record_file, dst)
                log.info(f"record file stored to {dst}")
                # copy strace log as well
                dst = os.path.join(self.store_core_dir, f"strace.{hash_str}.txt")
                shutil.copy(self.strace_log, dst)
                log.info(f"strace file stored to {dst}")
        # log.info("finish handle core dump")
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

    def compare_syscall(self, one_syscall):
        # compare with the first run value
        standard = one_syscall[0]
        for i in range(1, len(one_syscall)):
            if one_syscall[i][0] != standard[0]:
                return False
            if one_syscall[i][1] != standard[1]:
                return False
            if one_syscall[i][2] != standard[2]:
                return False
        return True

    def print_differ(self, order, differ, file_name):
        with open(file_name, 'w+') as f:
            f.write(f"syscall order after {differ}:\n")
            for i in range(differ, len(order)):
                f.write(f"num: {i}, syscall: {order[i][0]}, hash: {order[i][1]}\n")
                f.write(f"{order[i][2]}")

    def print_diff(self, diff_set, total_dict):
        print('printing diffset: ')
        for hash in diff_set:
            print(total_dict[hash])

    def check_new_syscall(self, orders):
        total_dict = {}
        sets = [set(), set(), set()]
        for i in range(len(orders)):
            for item in orders[i]:
                sets[i].add(item[1])
                total_dict[item[1]] = (item[0], item[2])
        differ_01 = sets[0] - sets[1]
        differ_10 = sets[1] - sets[0]
        differ_02 = sets[0] - sets[2]
        differ_20 = sets[2] - sets[1]
        self.print_diff(differ_01, total_dict)
        self.print_diff(differ_10, total_dict)
        self.print_diff(differ_02, total_dict)
        self.print_diff(differ_20, total_dict)

    def compare_syscall_orders(self, orders, tag):
        num_order = len(orders)
        min_len = len(orders[0])
        len_differ = False
        for i in range(0, num_order):
            length = len(orders[i])
            log.info(f"iteration {i}: {length} syscalls")
            if length != min_len:
                len_differ = True
            min_len = min(min_len, length)
        differ = -1
        for i in range(0, min_len):
            one_syscall = []
            for j in range(0, num_order):
                one_syscall.append(orders[j][i])
            equal = self.compare_syscall(one_syscall)
            if not equal:
                log.info(f'order differ from {i}th syscall')
                differ = i
                for j in range(0, num_order):
                    print(f'order {j}')
                    print(orders[j][i])
                break
        # print following syscalls, also print if length not match
        if differ < 0 and len_differ:
            differ = min_len
            print(f'no order different before minlen, but length differnt, min_len = {min_len}')
        if differ > 0:
            for i in range(num_order):
                log.info(f'differ syscalls in iteration {i}')
                self.print_differ(orders[i], differ, f'differ/{self.target_name}_{tag}_{i}')

    def clear_exit(self):
        self.kill_servers()
        self.kill_gdb()
        self.store_syscall_coverage()
        sys.exit(0)

    def check_syscall_order(self):
        log.info(f"check syscall order, run the vanila version three times")

        syscall_orders = []
        for i in range(0, 3):
            log.info(f"syscall order before client")
            self.clear_hash()
            self.run_interceptor_vanilla(True, None)
            syscall_orders.append(self.parse_syscall_order())
        self.compare_syscall_orders(syscall_orders, 'v')
        self.check_new_syscall(syscall_orders)
        self.print_differ(syscall_orders[0], 0, f'differ/{self.target_name}_allv_0')
        self.print_differ(syscall_orders[1], 0, f'differ/{self.target_name}_allv_1')
        self.print_differ(syscall_orders[1], 0, f'differ/{self.target_name}_allv_2')

        syscall_orders = []
        for client in self.target.get("clients"):
            log.info(f"syscall order after client")
            for i in range(0, 3):
                log.info(f"syscall order after client")
                self.clear_hash()
                self.run_interceptor_vanilla(False, client)
                syscall_orders.append(self.parse_syscall_order(False))
            self.compare_syscall_orders(syscall_orders, 'c')
            self.check_new_syscall(syscall_orders)
            self.print_differ(syscall_orders[0], 0, f'differ/{self.target_name}_allc_0')
            self.print_differ(syscall_orders[1], 0, f'differ/{self.target_name}_allc_1')
            self.print_differ(syscall_orders[1], 0, f'differ/{self.target_name}_allc_2')

    '''extend value list with invalid values, min, max and rand'''
    def extend_value_list(self, value_list):
        # deep copy
        new_value_list = copy.deepcopy(value_list)
        new_value_list.extend(['MIN', 'MAX', 'RANDOM'])
        return new_value_list

    def get_random_int(self):
        random_list = [random.randint(const.INT_MIN, const.INT_MAX),
                      random.randint(const.SHRT_MIN, const.SHRT_MAX),
                      random.randint(-sys.maxsize/2, sys.maxsize/2)]
        return random.choice(random_list)

    def remove_file(self, file):
        try:
            os.remove(file)
        except:
            pass

    def get_value_list(self, field_key, syscall_dict):
        value_list = None
        if self.value_method == ValueMethod.VALUE_ALL:
            if field_key is None or syscall_dict is None:
                log.error(f'field_key and sycall_dict should not be none for value_all method')
                self.clear_exit()
            value_list = syscall_dict.get(field_key)
            if value_list is None:
                # dose not have value in valid set, create an empty one
                value_list = []
            value_list = self.extend_value_list(value_list)
        elif self.value_method == ValueMethod.VALUE_RANDOM:
            value_list = ['RANDOM'] * const.RANDOM_REPEAT
        elif self.value_method == ValueMethod.VALUE_INVALID:
            value_list = ['MIN', 'MAX', 'RANDOM']
        return value_list

    def generate_random_file_name(self):
        rand_str = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        file_name = os.path.join(self.random_dir, f'RAND_{rand_str}')
        return file_name

    def extract_value_from_index(self, index_target):
        syscall_name = index_target[0]
        field_index = index_target[2]
        value_index = index_target[3]
        syscall_field_list = const.syscall_field_index[syscall_name]
        if field_index >= len(syscall_field_list):
            log.error(f'field_index out of bound: {field_index}/{len(syscall_field_list)}')
            self.clear_exit()
        if self.field_method == FieldMethod.FIELD_ALL:
            output_value_list = []
            for i in range(0, len(syscall_field_list)):
                output_value_list.append(self.generate_random_file_name())
            return output_value_list
        # append _v to the field name
        field_key = f'{syscall_field_list[field_index]}_v'
        # check if value index out of bound
        syscall_dict = self.value_dict.get(syscall_name)
        if syscall_dict is None:
            log.error(f'syscall {syscall_name} not found in value dict')
            self.clear_exit()

        value_list = self.get_value_list(field_key, syscall_dict)

        if value_index >= len(value_list):
            log.error(f'value_index out of bound: {value_index}/{len(value_list)}')
            self.clear_exit()
        # check if value is RANDOM
        if value_list[value_index] == "RANDOM":
            return self.generate_random_file_name()
        return value_list[value_index]

    def remove_random_file(self, value):
        # only one field, one value
        if self.field_method == FieldMethod.FIELD_ITER:
            if not isinstance(value, str) or "RAND" not in value:
                return
            self.remove_file(value)
        # all field, multiple file
        elif self.field_method == FieldMethod.FIELD_ALL:
            for item in value:
                if not isinstance(item, str) or "RAND" not in item:
                    continue
                self.remove_file(item)

    '''try next value/field, return 0 if success, -1 if no more value/field to explore'''
    def update_target(self, index_target, value_target):
        syscall_name = index_target[0]
        field_index = index_target[2]
        value_index = index_target[3]

        syscall_field_list = const.syscall_field_index[syscall_name]
        max_field_index = len(syscall_field_list)
        field_key = None
        syscall_dict = None
        if self.field_method == FieldMethod.FIELD_ITER:
            max_field_index = len(syscall_field_list)
            if field_index >= max_field_index:
                log.error(f'field_index out of bound: {field_index}/{max_field_index}')
                self.clear_exit()

            # append _v to the field name
            field_key = f'{syscall_field_list[field_index]}_v'

            # check if value index out of bound
            syscall_dict = self.value_dict.get(syscall_name)
            if syscall_dict is None:
                log.error(f'syscall {syscall_name} not found in value dict')
                self.clear_exit()
        elif self.field_method == FieldMethod.FIELD_RANDOM:
            max_field_index = const.RANDOM_REPEAT

        value_list = self.get_value_list(field_key, syscall_dict)

        # before increment, we need to remove the unused random file
        self.remove_random_file(value_target[3])
        # update value_index if possible
        if value_index + 1 < len(value_list):
            value_index += 1
        # value index cannot increase further, increment field index
        elif field_index + 1 < max_field_index:
            field_index += 1
            value_index = 0
        else:
            # both cannot increase further return -1
            return -1

        # update index target and value target
        index_target[2] = field_index
        index_target[3] = value_index

        # update value target
        if self.field_method == FieldMethod.FIELD_ITER:
            value_target[2] = field_index
            value_target[3] = self.extract_value_from_index(index_target)
        elif self.field_method == FieldMethod.FIELD_RANDOM:
            value_target[2] = random.randrange(max_field_index)
            value_target[3] = value_list[value_index]
        elif self.field_method == FieldMethod.FIELD_ALL:
            value_target[2] = -1
            value_target[3] = self.extract_value_from_index(index_target)
        return 0

    '''an recursive function'''
    def fuzz_with_targets(self, index_targets, value_targets, depth, before_poll=True, client=None):
        if depth >= self.max_depth:
            log.info('depth reach maximum')
            return
        log.info(f'current depth = {depth}')

        current_index_target = index_targets[depth]
        current_value_target = value_targets[depth]

        while True:
            new_syscall_dict = None
            new_unsupported_dict = None
            # run the fuzzer, retry 3 times if target syscall not appear
            log.debug(value_targets)
            for retry in range(0, const.INVOCATION_NOT_FOUND_RETRY):
                self.run_fuzzer_with_targets(value_targets, before_poll, client)
                # get the new list
                new_syscall_dict = self.parse_supported_hash(current_index_target[0], current_index_target[1])
                # parse_supported_hash will return None if target not found
                if new_syscall_dict is not None:
                    break
                else:
                    log.debug(f'target not found retry: {retry}')
            if new_syscall_dict is None:
                log.info('target syscall not found')
                stack_str = self.coverage_dict[f'{current_index_target[0]}@{current_index_target[1]}']
                if stack_str is not None:
                    log.info(stack_str)
                else:
                    log.info('stack string is None?')
                # skip this target if still not found
                return

            if depth + 1 < self.max_depth:
                log.debug(f'{len(new_syscall_dict)} new invocations found!')
                # update overall set and explore next depth
                self.overall_set.update(new_syscall_dict.keys())
                if len(new_syscall_dict) > 0:
                    log.info(f"number of overallset = {len(self.overall_set)}")
                for i in range(len(new_syscall_dict.keys())):
                    str_key = list(new_syscall_dict.keys())[i]
                    split_list = str_key.split('@')
                    stack_str = new_syscall_dict[str_key]
                    syscall = split_list[0]
                    hash_str = split_list[1]

                    # construct a target, syscall, hash_str, field index, field value
                    next_index_target = [syscall, hash_str, 0, 0]
                    next_value_target = [syscall, hash_str, 0, self.extract_value_from_index(next_index_target)]

                    # create a deepcopy of target list
                    next_index_targets = copy.deepcopy(index_targets)
                    next_value_targets = copy.deepcopy(value_targets)

                    next_index_targets.append(next_index_target)
                    next_value_targets.append(next_value_target)

                    log.info(f'recursive fuzz newly found syscall {str_key}:'
                             f' {i}/{len(new_syscall_dict)}, depth = {depth}, '
                             f'targets = {next_value_targets}')
                    log.info(stack_str)

                    # call the recursive function on the two new list
                    self.fuzz_with_targets(next_index_targets, next_value_targets, depth+1, before_poll, client)
            else:
                log.info('depth reach maximum')
            # try next value/field
            ret = self.update_target(current_index_target, current_value_target)
            if ret == -1:
                break

    def recursive_fuzz_main_loop(self, vanilla_list, before_poll=True, client=None):
        # generate initial target reference
        for i in range(len(vanilla_list.keys())):
            if i < self.start_skip:
                continue
            str_key = list(vanilla_list.keys())[i]
            split_list = str_key.split('@')
            log.warning(f'start recursive fuzz from vanilla_set '
                        f'{str_key}: {i}/{len(vanilla_list)}')
            syscall = split_list[0]
            hash_str = split_list[1]

            # construct a target, syscall, hash_str, field index, field value
            first_index_target = [syscall, hash_str, 0, 0]
            first_value_target = [syscall, hash_str, 0, self.extract_value_from_index(first_index_target)]

            index_targets = [first_index_target]
            value_targets = [first_value_target]
            self.store_syscall_coverage()
            # call the recursive function on the two list, pass by value
            self.fuzz_with_targets(copy.deepcopy(index_targets), copy.deepcopy(value_targets), 0, before_poll, client)


    def parse_and_get_unsupported_set(self):
        self.vanilla_list = []
        with open(self.hash_file) as fp:
            lines = fp.readlines()
            for line in lines:
                syscall, hash_str, stack = self.parse_syscall_stack_string_hash(line)
                if syscall not in self.supported:
                    self.unsupported_syscalls.add(syscall)
                else:
                    self.vanilla_list.append(syscall)

    def get_unsupported_syscalls(self):
        print('getting unsupported syscall set')
        self.clear_hash()
        ret = self.run_interceptor_vanilla(True, None)
        if ret == 0:
            log.info(f"vanilla cov run success (get unsupport list), before_poll = true")
        self.parse_and_get_unsupported_set()

        if self.server:
            if "clients" not in self.target:
                log.error(f"No client defiend for target {self.target_name}")
                return
            # test the part after polling separately for each client
            for client in self.target.get("clients"):
                self.clear_hash()
                ret = self.run_interceptor_vanilla(False, client)
                if ret == 0:
                    log.info(f"vanilla cov run success (get unsupport list), before_poll = false")
                self.parse_and_get_unsupported_set()
        log.warning(f'unsupported syscalls:\n{self.unsupported_syscalls}')

    def run_recursive_fuzz(self):
        log.info(f"running recursive fuzzer")
        self.clear_hash()
        # get the client
        client = None
        if self.server:
            if "clients" not in self.target:
                log.error(f"No client defiend for target {self.target_name}")
                return
            # test the part after polling separately for each client
            client = self.target.get("clients")[0]

        # run the vanilla version first, always use one run
        ret = self.run_interceptor_vanilla(False, client)
        if ret == 0:
            log.info(f"vanilla cov run success ! ")
        # generate vanila syscall list
        vanilla_list = self.parse_supported_hash(vanilla=True)
        # update overall set
        self.overall_set.update(vanilla_list.keys())
        print(f'size of vanilla_list is: {len(vanilla_list)}, size of overallset is {len(self.coverage_dict)}')
        if vanilla_list is None:
            log.error("failed to get vanilla list, terminate")
            self.clear_exit()
        # store coverage
        self.store_syscall_coverage()

        # start fuzzing
        if self.order_method == OrderMethod.ORDER_RECUR:
            self.recursive_fuzz_main_loop(vanilla_list, False, client)
        elif self.order_method == OrderMethod.ORDER_SEP:
            self.sep_fuzz_main_loop(client)
        elif self.order_method == OrderMethod.ORDER_ALL:
            self.all_fuzz_main_loop(client)

    def get_syscall_count(self):
        try:
            with open(self.count_file, 'r') as f:
                data = f.read()
                return int(data)
        except Exception as e:
            log.error(f"read count_file failed {e}")
            return -2

    def blind_fuzz_loop(self, client, target_syscall):
        # initialize the skip count
        skip_count = 0
        should_increase = True
        # get the max invocation of target from vanilla call:
        vanill_invocation = len(self.vanilla_list)
        if target_syscall is not None:
            vanill_invocation = 0
            for syscall in self.vanilla_list:
                if syscall == target_syscall:
                    vanill_invocation += 1
        log.warning(f"max invocation for target{target_syscall} is {vanill_invocation}")

        while should_increase:
            log.warning(f'skip count = {skip_count}')
            should_increase = False
            # for each skip_count increase
            result_list = []
            num_new_invocation = 0
            min_syscount = -1
            for i in range(self.iteration):
                # do the fuzzing
                fuzz_ret_code, retcode = self.run_fuzzer_with_targets(None, False, client, target_syscall, skip_count)

                # parse newly found syscalls:
                new_syscall_dict = self.parse_supported_hash()

                if new_syscall_dict is None:
                    log.error('new_syscall_dict should not be none without target')

                if len(new_syscall_dict) > 0:
                    # update overall set
                    self.overall_set.update(new_syscall_dict.keys())
                    log.debug(f"{len(new_syscall_dict)} new invocation found")
                    log.info(f"number of overallset = {len(self.overall_set)}")
                    num_new_invocation += len(new_syscall_dict)

                result_list.append((fuzz_ret_code, retcode, len(new_syscall_dict)))
                if fuzz_ret_code != FuzzResult.FUZZ_SUCCESS:
                    should_increase = True

                # get the syscall count returned by strace
                syscount = self.get_syscall_count()
                if syscount == -1:
                    log.error(f'syscall {target_syscall} not found')
                if min_syscount == -1:
                    min_syscount = syscount
                min_syscount = min(syscount, min_syscount)
            log.info(f"result list for {target_syscall}:{skip_count} is {result_list}")
            if min_syscount < 0:
                should_increase = False
            # decide if we should increase and how to increase
            # stop increase if skip_count > invocation*1.5 in vanilla run and no new invocation found
            if skip_count > vanill_invocation * 1.3 and num_new_invocation == 0 and should_increase:
                should_increase = False
                log.error(f'terminate because no new invocation found and skip count too larget')
            if should_increase:
                # increase the skip count:
                if self.skip_method == SkipMethod.SKIP_ONE:
                    skip_count = skip_count + 1
                elif self.skip_method == SkipMethod.SKIP_FAIL:
                    if min_syscount <= skip_count:
                        log.error(f'how could max_syscount {min_syscount} smaller than skip_count{skip_count}')
                        skip_count = skip_count + 1
                    # if min_syscount increase to much, just plus 1
                    elif min_syscount > (skip_count + (vanill_invocation * 0.2)):
                        log.error(f"sys count increase too much{min_syscount}, maybe enter infinite loop, change to +1")
                        skip_count = skip_count + 1
                    else:
                        skip_count = min_syscount

            self.store_syscall_coverage()

    # main loop of fuzz each syscall separately
    def sep_fuzz_main_loop(self, client):
        # for each supported syscall in vanilla run, do the fuzz
        # extract syscall_list
        fuzz_syscall_list = []
        for syscall in self.supported:
            if syscall in self.vanilla_list:
                fuzz_syscall_list.append(syscall)
        for i in range(len(fuzz_syscall_list)):
            target_syscall = fuzz_syscall_list[i]
            log.warning(f'start fuzz syscall {target_syscall} ({i}/{len(fuzz_syscall_list)})')
            self.blind_fuzz_loop(client, target_syscall)

    # main loop of fuzz all syscall
    def all_fuzz_main_loop(self, client):
        self.blind_fuzz_loop(client, None)

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
        log.warning(f"usupported set: {unsupported_set}")

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


    def run_interceptor_vanilla(self, before_poll=True, client=None, origin=False):
        if self.setup_func is not None:
            self.setup_func()
        # construct the strace command
        strace_cmd = f"{os.path.join(self.strace_dir, 'strace')} -ff"
        if self.server:
            cur_pid = os.getpid()  # pass pid to the strace, it will send SIGUSR1 back
            strace_cmd = f"{strace_cmd} -j {self.poll} -J {cur_pid}"

        # unnecessary for vanilla run
        # if not before_poll and client is not None:
        #     strace_cmd = f"{strace_cmd} -l"
        if self.print_trace:
            strace_cmd = f"{strace_cmd} -k"
        elif self.sc_cov:
            strace_cmd = f"{strace_cmd} -n {self.hash_file}"
            if self.not_write:
                strace_cmd = f"{strace_cmd} -N"
            if self.accept_hash > 0:
                strace_cmd = f"{strace_cmd} -Q {self.accept_hash}"

        strace_cmd = f"{strace_cmd} {self.command}"

        if origin:
            strace_cmd = self.command
        ld_path = ""
        if self.cache_unwind:
            ld_path = ld_cmd
        if self.sudo:
            strace_cmd = f"sudo -E {ld_path} {strace_cmd}"
        # strace_cmd = f"sudo -E /home/gavin/strace/strace -ff -j epoll_wait -J {cur_pid} -G -B 644 -K /home/gavin/rsyscall_fuzzer/controller/syscall.json -L /home/gavin/rsyscall_fuzzer/controller/record.txt -n syscov_memcached.txt /home/gavin/memcached-1.5.20/memcached -p 11111 -U 11111 -u gavin"
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
                                      close_fds=True,
                                      cwd=self.target_cwd,
                                      env=self.target_env)

        # wait for accept signal if it is a server
        if self.server:
            # ignore signal
            # signal.pthread_sigmask(signal.SIG_UNBLOCK, [const.ACCEPT_SIG])
            # Wait for sigmax-7, or acknowledge if it is already pending
            start = time.time()

            # use polling instead of timeout
            wait_start = time.time()
            wait_end = time.time()
            log.debug("wait for server's signal ...")
            while wait_end - wait_start < self.poll_time:
                ret = signal.sigtimedwait([const.ACCEPT_SIG], 0)  # poll the signal
                if ret is not None:  # singal received
                    break
                # check server state
                retcode = self.srv_p.poll()
                if retcode is not None:
                    log.debug(f'server terminated before reach accept, retcode = {retcode}')
                    break
                wait_end = time.time()
            signal.pthread_sigmask(signal.SIG_UNBLOCK, [const.ACCEPT_SIG])
            if ret is None:  # timeout
                log.debug("signal timeout!")
                retcode = self.srv_p.poll()
                if retcode is not None:
                    log.debug(f'server terminated before reach accept, retcode = {retcode}')
                self.kill_servers()
                sys.exit("signal wait timeout during vanilla run, terminate the process")

            end = time.time()
            self.accept_time += (end - start)
            if ret:
                logging.debug(f"sig {const.ACCEPT_SIG} received!")
            else:
                sys.exit("signal wait timeout during vanilla run, terminate the process")

            # check if this turn only test before poll:
            if before_poll:
                # check if the server crashes,
                ret = self.srv_p.poll()
                if ret is None: # terminate the server and return
                    os.killpg(os.getpgid(self.srv_p.pid), signal.SIGTERM)
                    start = time.time()
                    self.srv_p.wait()  # wait until strace properly save the output
                    end = time.time()
                    self.after_time += (end-start)
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
            start = time.time()
            for j in range(const.CLIENT_RETRY):
                client_ret = client()
                if client_ret == 0:
                    break
                else:
                    print(f'retry: {j}')
            end = time.time()
            self.client_time += (end - start)
            if client_ret != 0:
                self.kill_servers()
                sys.exit("error: client failed during vanilla run!")
            else:
                log.info("client success during vanilla run!")
                # check if server terminated
                if self.retcode is not None:
                    # wait for server to terminate
                    start = time.time()
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
                    end = time.time()
                    self.after_time += (end - start)

                retcode = self.srv_p.poll()
                if retcode is None:
                    os.killpg(os.getpgid(self.srv_p.pid), signal.SIGTERM)
                    start = time.time()
                    self.srv_p.wait()  # wait until strace properly save the output
                    end = time.time()
                    self.after_time += (end-start)
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
                if self.accept_hash > 0:
                    strace_cmd = f"{strace_cmd} -Q {self.accept_hash}"


            strace_cmd = f"{strace_cmd} {self.command}"

            if self.cache_unwind:
                ld_path = ld_cmd

            if self.sudo:
                strace_cmd = f"sudo -E {ld_path} {strace_cmd}"

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
                # signal.signal(const.ACCEPT_SIG, signal.SIG_IGN)
                # Block signal until sigwait (if caught, it will become pending)
                signal.pthread_sigmask(signal.SIG_BLOCK, [const.ACCEPT_SIG])
                # signal.pthread_sigmask(signal.SIG_UNBLOCK, [const.ACCEPT_SIG])
                self.srv_p = subprocess.Popen(args,
                                              stdin=subprocess.PIPE,
                                              stdout=self.strace_log_fd,
                                              stderr=self.strace_log_fd,
                                              preexec_fn=os.setsid,
                                              cwd=self.target_cwd,
                                              close_fds=True,
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
                    # time.sleep(0.5)
                    retcode = self.srv_p.poll()
                    log.debug("check server exist before wait for signal")
                    if retcode is not None:
                        failed_iters.append((i, retcode))
                        should_increase = True
                    else:
                        # use polling instead of timeout
                        wait_start = time.time()
                        wait_end = time.time()
                        log.debug("wait for server's signal ...")
                        while wait_end - wait_start < self.poll_time:
                            ret = signal.sigtimedwait([const.ACCEPT_SIG], 0)  # poll the signal
                            if ret is not None:  # singal received
                                break
                            # check server state
                            retcode = self.srv_p.poll()
                            if retcode is not None:
                                log.debug(f'server terminated before reach accept, retcode = {retcode}')
                                failed_iters.append((i, retcode))
                                should_increase = True
                                break
                            wait_end = time.time()
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
                            # exit(0)
                        else:
                            log.debug("signal received!")
                            # check if this turn only test before poll:
                            if before_poll:
                                # check if the server crashes,
                                ret = self.srv_p.poll()
                                if ret is None:  # terminate the server and return
                                    os.killpg(os.getpgid(self.srv_p.pid), signal.SIGTERM)
                                    log.debug("terminate the server, wait until it terminate..")
                                    try:
                                        self.srv_p.wait(5)  # wait until strace properly save the output
                                    except:
                                        log.debug("server terminate timeout, force kill")
                                        self.kill_servers()
                                    log.debug("server terminated")
                                # server terminate before client, report error
                                else:
                                    self.kill_servers()
                                    failed_iters.append((i, 'exit_b'))
                                    should_increase = True
                            else:  # after polling, connect a client
                                log.debug("connecting client ...")
                                for j in range(const.CLIENT_RETRY):
                                    client_ret = client()
                                    if client_ret == 0:
                                        break
                                log.debug(f"client ret code {client_ret}")
                                if client_ret != 0:
                                    log.debug(f"client failed, kill server, wait ... ")
                                    os.killpg(os.getpgid(self.srv_p.pid), signal.SIGTERM)
                                    try:
                                        self.srv_p.wait(5)  # wait until strace properly save the output
                                    except:
                                        log.debug("server terminate timeout, force kill")
                                        self.kill_servers()
                                    log.debug(f"server terminated ... ")
                                    failed_iters.append((i, 'client_f'))
                                    should_increase = True
                                else:  # client success, check state of server
                                    try:  # wait for server to terminate after client
                                        retcode = self.srv_p.wait(timeout=self.timeout)
                                    except (TimeoutError, subprocess.TimeoutExpired):
                                        log.debug("server still exist after client, try to terminate it ...")
                                        os.killpg(os.getpgid(self.srv_p.pid), signal.SIGTERM)
                                        try:
                                            self.srv_p.wait(5)  # wait until cov properly save the output
                                        except:
                                            log.error("server terminate time out, force kill")
                                            self.kill_servers()
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
                core_ret = self.handle_core_dump(skip_count=skip_count)
                if core_ret is None:
                    print("are you kiddingme ? how could this be NOne?")
                elif core_ret > 0:
                    self.kill_servers()
                    failed_iters.append((i, 'core'))
                    should_increase = True
                # for iteration, code in failed_iters:
                #     if iteration == i:
                #         log.info(f"{iteration}: {code}")
                self.parse_hash(False)
                log.debug("finish parse hash")

            # output list if necessary
            log.info(failed_iters)
            if should_increase:
                skip_count = skip_count+1

    def convert_value_target_to_string(self, value_target):
        value_string = f'{value_target[3]}'
        # the value string for FIELD_ALL will contain all the values joined with @
        if self.field_method == FieldMethod.FIELD_ALL:
            sep = '@'
            value_list_string = map(str, value_target[3])
            value_string = sep.join(value_list_string)
        return f'{value_target[0]} {value_target[1]} {value_target[2]} {value_string}\n'

    def parse_record_file(self):
        newly_fuzzed = []
        with open(self.record_file) as fp:
            lines = fp.readlines()
            for line in lines:
                if "syscall: " in line and "hash: " in line:
                    parts = line.split(", hash: ")
                    syscall = parts[0].split(": ")[-1]
                    hash_str = parts[1].strip()
                    str_key = f'{syscall}@{hash_str}'
                    if str_key not in self.fuzzed_set:
                        self.fuzzed_set.add(str_key)
                        newly_fuzzed.append(str_key)
        if len(newly_fuzzed) > 0:
            log.info(f"newly fuzzed {len(newly_fuzzed)} syscalls. total={len(self.fuzzed_set)}, {newly_fuzzed}")

    def run_fuzzer_with_targets(self, value_targets, before_poll, client, target_syscall=None, skip_count=-1):
        if value_targets is None and self.order_method == OrderMethod.ORDER_RECUR:
            log.error('value_target should not be none for recursive fuzz')
            self.clear_exit()
        if value_targets is not None:
            # write the fuzzing target into file
            with open(self.reference_file, 'w+') as f:
                for value_target in value_targets:
                    # syscall, hash, field_idnex, value
                    f.write(self.convert_value_target_to_string(value_target))
        # construct strace command
        strace_cmd = f"{os.path.join(self.strace_dir, 'strace')} -ff"
        if self.server:
            cur_pid = os.getpid()  # pass pid to the strace, it will send SIGUSR1 back
            strace_cmd = f"{strace_cmd} -j {self.poll} -J {cur_pid}"

        #  -G means start fuzzing
        strace_cmd = f"{strace_cmd} -G"

        # -R means recursive fuzz, provide ref file
        if value_targets is not None:
            strace_cmd = f"{strace_cmd} -R {self.reference_file}"

        # add record file if set
        if self.record_file is not None:
            strace_cmd = f"{strace_cmd} -L {os.path.abspath(self.record_file)}"

        # always add hash_file
        strace_cmd = f"{strace_cmd} -n {self.hash_file}"
        if self.accept_hash > 0:
            strace_cmd = f"{strace_cmd} -Q {self.accept_hash}"

        # fuzz all or fuzz separately, need to provide a supported syscall list for fuzz all
        if self.order_method == OrderMethod.ORDER_ALL:
            strace_cmd = f"{strace_cmd} -H ALL -K {os.path.abspath(self.syscall_config)}"
        elif self.order_method == OrderMethod.ORDER_SEP:
            if target_syscall is None:
                log.error('target sys call should not be none for ORDER_SEP')
                self.clear_exit()
            strace_cmd = f"{strace_cmd} -H {target_syscall}"

        if self.order_method == OrderMethod.ORDER_ALL or self.order_method == OrderMethod.ORDER_SEP:
            # should always have a skip_count for those two method, and always have a count_file specified
            if skip_count == -1:
                log.error(f'skip count must be set for order method: {self.order_method}')
                self.clear_exit()
            strace_cmd = f"{strace_cmd} -B {skip_count} -N {os.path.abspath(self.count_file)}"

        strace_cmd = f"{strace_cmd} {self.command}"

        if self.cache_unwind:
            ld_path = ld_cmd

        if self.sudo:
            strace_cmd = f"sudo -E {ld_path} {strace_cmd}"

        log.debug(f"start fuzzing with command {strace_cmd}")
        args = shlex.split(strace_cmd)

        # do some clean up before run
        self.clear_cores()
        self.clear_record()
        self.clear_strace_log()
        self.clear_hash()
        # make sure no server is running
        self.kill_servers()
        # initialize the retcode with a magic number
        retcode = 10086
        fuzz_ret_code = FuzzResult.FUZZ_SUCCESS
        if self.setup_func is not None:
            self.setup_func()

        # Block signal until sigwait (if caught, it will become pending)
        signal.pthread_sigmask(signal.SIG_BLOCK, [const.ACCEPT_SIG])

        # running...
        try:
            self.srv_p = subprocess.Popen(args,
                                          stdin=subprocess.PIPE,
                                          stdout=self.strace_log_fd,
                                          stderr=self.strace_log_fd,
                                          preexec_fn=os.setsid,
                                          cwd=self.target_cwd,
                                          close_fds=True,
                                          env=self.target_env)
        except:
            proc = psutil.Process()
            log.error(f'opened files: {proc.open_files()}, too many open file?')
            self.kill_servers()
            fuzz_ret_code = FuzzResult.FUZZ_ERROR
            return fuzz_ret_code, retcode

        if not self.server:
            if self.input:
                self.srv_p.communicate(self.input.encode("utf-8").decode('unicode_escape').encode("utf-8"))
            try:
                retcode = self.srv_p.wait(self.timeout)  # wait for 2 second, if not ret, something happened
            except subprocess.TimeoutExpired:
                # timeout, kill the program
                self.kill_servers()
                fuzz_ret_code = FuzzResult.FUZZ_EXECTIMEOUT
            else:
                if self.retcode != retcode:
                    self.kill_servers()
                    fuzz_ret_code = FuzzResult.FUZZ_RETNOTMATCH

        else:  # handle servers
            # check if server exist before wait for signal (save time)
            # time.sleep(0.5)
            retcode = self.srv_p.poll()
            log.debug("check server exist before wait for signal")
            if retcode is not None:
                log.debug('server exit before signal')
                fuzz_ret_code = FuzzResult.FUZZ_EXITB4POLL
            else:
                # use polling instead of timeout
                wait_start = time.time()
                wait_end = time.time()
                log.debug("wait for server's signal ...")
                while wait_end - wait_start < self.poll_time:
                    ret = signal.sigtimedwait([const.ACCEPT_SIG], 0)  # poll the signal
                    if ret is not None: # singal received
                        break
                    # check server state
                    retcode = self.srv_p.poll()
                    if retcode is not None:
                        log.debug(f'server terminated before reach accept, retcode = {retcode}')
                        fuzz_ret_code = FuzzResult.FUZZ_EXITB4POLL
                        break
                    wait_end = time.time()
                signal.pthread_sigmask(signal.SIG_UNBLOCK, [const.ACCEPT_SIG])
                if ret is None:  # timeout
                    log.debug("signal timeout!")
                    retcode = self.srv_p.poll()
                    fuzz_ret_code = FuzzResult.FUZZ_SIGTIMEOUT
                    if retcode is not None:
                        fuzz_ret_code = FuzzResult.FUZZ_EXITB4POLL
                        log.debug(f'server terminated before reach accept, retcode = {retcode}')
                    self.kill_servers()
                else:
                    log.debug("signal received!")
                    # check if this turn only test before poll:
                    if before_poll:
                        # check if the server crashes,
                        retcode = self.srv_p.poll()
                        if retcode is None:  # terminate the server and return
                            os.killpg(os.getpgid(self.srv_p.pid), signal.SIGTERM)
                            log.debug("terminate the server, wait until it terminate..")
                            try:
                                self.srv_p.wait(5)  # wait until strace properly save the output
                            except:
                                log.debug("server terminate timeout, force kill")
                                self.kill_servers()
                            log.debug("server terminated")
                        # server terminate before client, report error
                        else:
                            self.kill_servers()
                    else:  # after polling, connect a client
                        log.debug("connecting client ...")
                        for j in range(const.CLIENT_RETRY):
                            client_ret = client()
                            if client_ret == 0:
                                break
                        log.debug(f"client ret code {client_ret}")
                        if client_ret != 0:
                            log.debug(f"client failed, kill server, wait ... ")
                            # if self.order_method != OrderMethod.ORDER_RECUR:
                            #     try:
                            #         self.srv_p.wait(5)  # wait until strace properly save the output
                            #     except:
                            #         pass
                            fuzz_ret_code = FuzzResult.FUZZ_CLIENTFAIL
                            self.kill_servers()
                            log.debug(f"server terminated ... ")
                        else:  # client success, check state of server
                            if self.retcode is not None: # server should exit
                                try:  # wait for server to terminate after client
                                    retcode = self.srv_p.wait(timeout=self.timeout)
                                except (TimeoutError, subprocess.TimeoutExpired):
                                    log.debug("server still exist after client, try to terminate it ...")
                                    os.kill(self.srv_p.pid, signal.SIGTERM)
                                    fuzz_ret_code = FuzzResult.FUZZ_EXECTIMEOUT
                                    try:
                                        self.srv_p.wait(8)  # wait until cov properly save the output
                                    except:
                                        log.error("server terminate time out, force kill")
                                        self.kill_servers()
                                else:
                                    log.debug("server terminated!")
                                    if retcode != self.retcode:
                                        fuzz_ret_code = FuzzResult.FUZZ_RETNOTMATCH
                            # if server suppose to run inifinitely, just kill it
                            else:
                                self.kill_servers()

        # handle core dumped
        core_ret = self.handle_core_dump_script(retcode, value_targets, skip_count)
        if core_ret is None:
            log.error("are you kiddingme ? how could this be NOne?")
        if retcode == -11 and core_ret == 0:
            log.error(f'Retcode is -11 but no core found, target = {value_targets}')
        elif core_ret > 0:
            self.kill_servers()
            fuzz_ret_code = FuzzResult.FUZZ_COREDUMP
        # parse record file and check if new syscall get fuzzed
        self.parse_record_file()

        if retcode == 1:
            stored_error = os.path.join(self.errorlog_dir, f"err_{self.errorcount}.txt")
            shutil.copy(self.strace_log, stored_error)
            log.error(f"strace retcode is 1, store file to {stored_error}")
            self.errorcount += 1
        return fuzz_ret_code, retcode
