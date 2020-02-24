import logging
import sys
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

    def run(self):
        # test the application or part before polling in a server
        self.test_target(True)

        # if target is a server, also fuzz the second part
        if self.target.get("server", False):
            if "clients" not in self.target:
                log.error(f"No client defiend for target {self.target_name}")
                return
            # test the part after polling separately for each client
            for client in self.target.get("clients"):
                self.test_target(False, client)

    def test_target(self, before_poll=True, client=None):
        # run the vanila version first

        pass

    def run_interceptor(self):
        pass
