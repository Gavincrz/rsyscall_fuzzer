import gdb
top_stack = gdb.newest_frame()
iter = gdb.FrameIterator.FrameIterator(top_stack)

final_stack_str = ''
for frame in iter:
    sal = frame.find_sal()
    line = sal.line
    symtab = sal.symtab
    fullname = '???nosymtab???'
    if symtab is not None:
        fullname = symtab.fullname()
    final_stack_str = f'{final_stack_str}{fullname}:{line}'

# output the string
with open("gdb_stack_str.txt", "w+") as file:
    file.write(final_stack_str)