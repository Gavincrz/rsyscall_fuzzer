import signal
import re

ACCEPT_SIG = int(signal.SIGRTMAX-7)
CLIENT_DELAY = 1

''' gdb patterns '''
top_stack_pattern = re.compile("#.*")
at_pattern = re.compile("#.* at .*")
not_found_pattern = re.compile(".*No such file or directory.*")
empty_history_pattern = re.compile(".*The history is empty.*")
enable_stack_trace = False
