import os
import json
import subprocess
import shlex
from pathlib import Path
import rscfuzzer.const as const

output_path = "/home/gavin/llvm_output.txt"
wrapper_th = 4


def get_source_file_list(path):
    file_list = []
    if os.path.isdir(path):
        for subpath in Path(path).rglob('*.c'):
            file_list.append(os.path.join(path, subpath.name))
    elif os.path.isfile(path):
        if "compile_commands.json" not in path:
            return
        with open(path) as f:
            json_array = json.load(f)
            for item in json_array:
                file_list.append(item['file'])

    print(f"{len(file_list)} files found!")
    return file_list


module_dict = {}
func_dict = {}


def parse_file(path):
    global module_dict, func_dict
    if not os.path.exists(path):
        return
    with open(path) as fp:
        lines = fp.readlines()
        cur_module = path
        temp_module_set = []
        temp_func_set = []
        temp_func_contain = False
        cur_function = None
        for line in lines:
            if "Module: " in line:
                cur_module = line.split(' ')[1].rstrip('\r\n')
                temp_module_set = []
                if cur_module in module_dict.keys():
                    temp_module_set = module_dict[cur_module]
            elif "Function: " in line:
                cur_function = line.split(' ')[1].rstrip('\r\n')
                temp_func_set = []
                temp_func_contain = None
                if cur_function in func_dict.keys():
                    temp_func_set = func_dict[cur_function][0]
                    temp_func_contain = func_dict[cur_function][1]
            elif "Module end" in line:
                # write back module
                module_dict[cur_module] = temp_module_set
            elif "Function end" in line:
                # write back function
                func_dict[cur_function] = [temp_func_set, temp_func_contain, 0] # set, contain syscall flag, called times
            else:
                called = line.rstrip('\r\n')
                temp_module_set.append(called)
                temp_func_set.append(called)
                if called in const.all_syscall:
                    temp_func_contain = True


def contain_syscall(func, depth=0):
    value = func_dict.get(func)
    if value is None:
        return False
    if value[1] is None:
        if depth > 10:
            func_dict[func] = [value[0], False, value[2]]
            return False
        contain = False
        for called in value[0]:
            contain = contain_syscall(called, depth+1)
            if contain:
                break
        func_dict[func] = [value[0], contain, value[2]]
        return contain
    return value[1]


def count_syscalls(path):
    parse_file(path)
    # global module_dict, func_dict
    # file_list = get_source_file_list(path)
    # for file in file_list:
    #     if os.path.exists(output_path):
    #         os.remove(output_path)
    #     cmd = f"clang -Xclang -load -Xclang " \
    #           f"/home/gavin/syscallpass/build/syscallcounter/libSyscallCounter.so " \
    #           f"{file}"
    #     args = shlex.split(cmd)
    #     subprocess.run(args)
    #     print(cmd)
    #     parse_file(output_path)
    module_count = 0
    for module, value in module_dict.items():
        syscall_count = 0
        for item in value:
            if item in const.all_syscall:
                syscall_count += 1
        if syscall_count > 0:
            module_count += 1
            print(f"module: {module} : syscall number: {syscall_count}")
    print(f"{module_count} / {len(module_dict)} contains syscalls")

    # get syscall invokation times
    for func, value in func_dict.items():
        contain_syscall(func)
        for func2 in value[0]:
            value2 = func_dict.get(func2)
            if value2 is None:
                continue
            func_dict[func2] = [value2[0], value2[1], value2[2]+1]

    func_count = 0
    called_count = 0
    wrapper_list = []
    for func, value in func_dict.items():
        syscall_count = 0
        for item in value[0]:
            if item in const.all_syscall:
                syscall_count += 1
        if syscall_count > 0:
            func_count += 1
            print(f"Function: {func} : syscall number: {syscall_count}")
        if value[1] and value[2] >= wrapper_th:
            wrapper_list.append((func, value[2]))
        if value[2] > 0:
            called_count += 1
    print(f"{func_count}/{called_count}/{len(func_dict)} functions contain syscalls")
    print(f"{len(wrapper_list)} wrapper functions when threshold = 4")
    print(wrapper_list)




