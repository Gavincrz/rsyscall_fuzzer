import logging
import sys
import os
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
        ret = self.run_interceptor(before_poll, client, True)

    def run_interceptor(self, before_poll=True, client=None, vanilla=True):
        # construct the strace command
        strace_cmd = f"{os.path.join(self.strace_dir, 'strace')} -ff"
        if self.server:
            cur_pid = os.getpid()  # pass pid to the strace, it will send SIGUSR1 back
            strace_cmd = f"{strace_cmd} -j {self.poll} -J {cur_pid}"
        # only test the part after polling (include the polling syscall)
        if not before_poll and client is not None:
            strace_cmd = f"{strace_cmd} -l"
        
        return 0
