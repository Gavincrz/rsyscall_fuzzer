import gdb

try:
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
        final_stack_str = f'{final_stack_str}{fullname}:{line}\n'

    # output the string
    with open("gdb_stack_str.txt", "w+") as file:
        file.write(final_stack_str)
except Exception as e:
    with open("gdb_stack_str.txt", "w+") as file:
        file.write(f'gdb script error: {e}\n')

# close gdb
gdb.execute('quit')