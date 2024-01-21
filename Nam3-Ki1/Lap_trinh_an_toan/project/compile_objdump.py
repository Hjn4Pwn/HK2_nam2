import os
import re
import subprocess

get_funct = {"babybof": "print_flag",
             "babysteps": "ask_baby_name",
             "beginners_pwn": "win",
             "bof3": "read_canary",
             "cheap": "readn",
             "crash_override": "win_crash",
             "function_overwrite": "calculate_story_score",
             "Guest_game_1": "increment",
             "Guest_game_2": "do_stuff",
             "handy_shellcode": "vuln",
             "justpwnit": "justpwnit",
             "leak_flag": "vuln_leak",
             "picker_IV": "win_IV",
             "program-redacted": "tgetinput",
             "reader": "menu",
             "record_keeper": "get_record",
             "ropfu": "vuln_ropfu",
             "RPS": "play",
             "save_tyger2": "cell",
             "share": "check",
             "stack_cache": "UnderConstruction",
             "stonk": "free_portfolio",
             "stringzz": "printMessage1",
             "Unsubscriptions_Are_Free": "processInput",
             "x-sixty-what": "vuln_60"
             }


def extract_bracketed_value(input_str):
    match = re.search(r'\[(.*?)\]', input_str)
    if match:
        return 1
    return None


def isnumber(input_str):
    pattern = re.compile(r'^(0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?|[0-9]+)$')
    match = pattern.match(input_str)
    if match:
        return 1
    return 0


def quick_check(line, check, arr):
    if check is None:
        return line
    register = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp',
                'esp', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi',
                'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12',
                'r13', 'r14', 'r15', 'AH', 'AL', 'AX', 'BH', 'BL',
                'BX', 'CH', 'CL', 'CX', 'DH', 'DL', 'DX',
                'SP', 'BP', 'SI', 'DI']

    jmp_call = ['jnc', 'jl', 'jmp', 'jb', 'je', 'jns', 'jnle', 'jno',
                'jpo', 'jp', 'jpe', 'js', 'jne', 'jz', 'jo', 'jnl',
                'jg', 'jrcxz', 'jc', 'jge', 'jnz', 'jae', 'jng', 'jnp',
                'jcxz', 'jnae', 'jnge', 'jbe', 'jna', 'jle', 'ja', 'jecxz',
                'jnb', 'jnbe']

    if check is not None and extract_bracketed_value(check):
        if check.count("+") == 1:
            line = line.replace(check, "typethree", 1)
        elif check.count("+") == 2:
            line = line.replace(check, "typefour", 1)
        else:
            line = line.replace(check, "typetwo", 1)
        return line

    if isnumber(check):
        line = line.replace(check, "typefive", 1)
        return line

    if arr[0] == "call":
        line = line.replace(check, "typesix", 1)
        return line

    if arr[0] in jmp_call:
        line = line.replace(check, "typeseven", 1)
        return line

    if check is not None and check in register:
        line = line.replace(check, "typeone", 1)
        return line

    line = line.replace(check, "typeeight", 1)

    return line


def normalize(line):
    arr = []
    line = line.lower()
    line = line.replace('ptr ', '')
    line = line.replace('offset ', '')
    line = line.replace('xmmword ', '')
    line = line.replace('dword ', '')
    line = line.replace('qword ', '')
    line = line.replace('word ', '')
    line = line.replace('byte ', '')
    line = line.replace('short ', '')
    line = line.replace('-', '+')
    line = line.rstrip()
    original_line = line

    if len(line.split()) >= 2:
        arr.append(line.split()[0])  # 1
        line = line.replace(arr[0], "", 1).lstrip()
        if len(line.split(",")) == 2:
            arr.append(line.split(",")[0])  # 2
            arr.append(line.split(",")[1])  # 3
        else:
            arr.append(line)  # 2
            arr.append(None)
    else:
        arr.append(line)  # 1
        arr.append(None)
        arr.append(None)

    original_line = quick_check(original_line, arr[1], arr)
    original_line = quick_check(original_line, arr[2], arr)

    processed_line = re.sub(r'\s+', ' ', original_line)
    processed_line = processed_line.replace(",", " ")

    return processed_line


def get_asm_code_of_funct(file_path, search_string, output_file_path):
    result = ""

    try:
        with open(file_path, 'r') as file:
            content = file.read()

            start_index = content.find(search_string)

            if start_index != -1:
                end_index = content.find('\n\n', start_index)

                if end_index != -1:
                    result_content = content[start_index:end_index]

                    result_content = '\n'.join(line.split('#')[0]
                                               for line in result_content.split('\n'))

                    for line in result_content.split('\n'):
                        if search_string not in line:
                            result += "".join(line.split(":")[1].lstrip())
                            result += "\n"

                    with open(output_file_path, 'w') as output_file:
                        output_file.write(result.strip())

                    return f"Search result saved to {output_file_path}"
                else:
                    return "Not Found"
            else:
                return f"Can't find {search_string}"
    except FileNotFoundError:
        return f"{file_path} not found"
    except Exception as e:
        return f"Error: {e}"


def compile_files(source_dir):
    if not os.path.exists(source_dir):
        print(f"'{source_dir}' not found")
        return

    for filename in os.listdir(source_dir):
        if filename.endswith(".c"):
            file_path = os.path.join(source_dir, filename)
            source_base_dir = os.path.dirname(file_path)
            funct_name = get_funct[filename.split(".")[0]]
            search_funct = f"<{funct_name}>:"
            for opt_level in ["O0", "O1", "O2", "O3"]:
                output_file = f"{os.path.splitext(filename)[0]}_{opt_level}_gcc"
                output_path = os.path.join(source_base_dir, output_file)
                gcc_command = f"gcc -{opt_level} -w {file_path} -o {output_path}"
                subprocess.run(gcc_command, shell=True)

                asm_file = f"{os.path.splitext(output_path)[0]}.txt"
                objdump_command = f"objdump --disassemble --no-show-raw-insn --disassembler-options=intel {output_path} > {asm_file}"
                subprocess.run(objdump_command, shell=True)

                output_asm = f"{os.path.splitext(output_path)[0]}_{funct_name}.txt"
                get_asm_code_of_funct(asm_file, search_funct, output_asm)

                with open(output_asm, "r") as f:
                    content = f.read()

                result = ""
                output_file_path = f"{os.path.splitext(output_path)[0]}_{funct_name}_NORMALIZE.txt"
                for line in content.split("\n"):
                    result += normalize(line)
                    result += "\n"

                with open(output_file_path, 'w') as output_file:
                    output_file.write(result.strip())

            for opt_level in ["O1", "O2", "O3", "Os"]:
                output_file = f"{os.path.splitext(filename)[0]}_{opt_level}_clang"
                output_path = os.path.join(source_base_dir, output_file)
                clang_command = f"clang -{opt_level} -w {file_path} -o {output_path}"
                subprocess.run(clang_command, shell=True)

                asm_file = f"{os.path.splitext(output_path)[0]}.txt"
                objdump_command = f"objdump --disassemble --no-show-raw-insn --disassembler-options=intel {output_path} > {asm_file}"
                subprocess.run(objdump_command, shell=True)

                output_asm = f"{os.path.splitext(output_path)[0]}_{funct_name}.txt"
                get_asm_code_of_funct(asm_file, search_funct, output_asm)

                with open(output_asm, "r") as f:
                    content = f.read()

                result = ""
                output_file_path = f"{os.path.splitext(output_path)[0]}_{funct_name}_NORMALIZE.txt"
                for line in content.split("\n"):
                    result += normalize(line)
                    result += "\n"

                with open(output_file_path, 'w') as output_file:
                    output_file.write(result.strip())

    print("Compile and objdump completed!!!")


template = "./data/process_data/"
for i in range(1, 26):
    source_directory = f"./data/process_data/{str(i)}"
    compile_files(source_directory)
