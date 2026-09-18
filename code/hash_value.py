import csv
import re
import subprocess
import shutil
import hashlib
import os
import time
from pathlib import Path
from bs4 import BeautifulSoup
import sys
import multiprocessing



def get_html_lines(my_html_path):
    with open(my_html_path, 'r', encoding = 'utf-8') as file:
        lines = file.readlines()


    return lines


def get_html_content(my_html_path):
    with open(my_html_path, 'r', encoding = 'utf-8') as file:
        html_content = file.read()
    return html_content




def get_last_line_col(my_text,my_first_line):

    one_line_flag = False


    # one line function
    my_first_count = 1
    function_text = ''
    line_count = 0
    my_first_line = re.sub(r'\s+', '', my_first_line)
    for my_first_line_index in my_first_line:
        #print(my_first_line_index)
        if my_first_line_index == '{':
            my_first_count += 1
        elif my_first_line_index == '}':
            my_first_count = my_first_count - 1
            #print(my_first_count)
            if my_first_count == 0:
                #print('return',function_text)
                one_line_flag = True
                return line_count, function_text, one_line_flag
        function_text += my_first_line_index

    # one line with multiple functon 




    # multiple lines function
    function_text = ''
    comment_flag = True
    return_count = 1
    line_count = 1 
    
    for my_line in my_text:
        previous_char = ''
        comment_flag = True
        for i,char in enumerate(my_line):
            if previous_char + char == '//':
                comment_flag = False

            if char == '{' and comment_flag:
                pre_char_check = my_line[i-1] 
                aft_char_check = my_line[i+1]
                check_char = pre_char_check + char + aft_char_check
                if check_char == "'{'":
                    pass
                else:
                    return_count += 1
            elif char == '}' and comment_flag:
                pre_char_check = my_line[i-1] 
                aft_char_check = my_line[i+1]
                check_char = pre_char_check + char + aft_char_check
                if check_char == "'}'":
                    pass
                else:
                    return_count = return_count - 1

                if return_count == 0:
                    return line_count, function_text, one_line_flag
            function_text = function_text + char
            previous_char = char
        line_count += 1


def remove_whitespace(my_text):
    return_str = re.sub(r'\s+', '', my_text)
    return_str = "{" + return_str + "}"
    return return_str

def get_hash(my_text, my_no_text):
    global save_total_hash_path_
    global no_crash_total_hash_path_

    #print(my_no_text)
    #print(my_text)
    hash_value = hashlib.sha256(my_text.encode()).hexdigest()
    hash_save_path_ = os.path.join(save_total_hash_path_ , f"{hash_value}.txt")
    no_crash_hash_save_path_ = os.path.join(no_crash_total_hash_path_, f"{hash_value}.txt") 
    if not os.path.exists(hash_save_path_):
        with open(no_crash_hash_save_path_, 'w') as f:
            f.write(my_no_text)

    #print(hash_value)
    #hash_object = hashlib.sha256(cleaned_enter_function_str.encode())
    #hex_dig = hash_object.hexdigest()
    return hash_value





def count_js_function(my_path):
    total_hash_function_dict = {}
    #function_pattern = re.compile(r'\bfunction\b\s*(\w*\s*)?\(\s*.*?\s*\)\s*{')
    function_pattern = re.compile(r'\bfunction\b\s*([^\s(]*\s*)?\(\s*.*?\s*\)\s*{')
    split_my_path = my_path.split('/')
    save_file_root = ''

    for index in range(len(split_my_path)-1):
        save_file_root += '/' + split_my_path[index]
    
    save_file_path = save_file_root + '/added_console_index.html'
    save_total_hash_function_path = save_file_root + '/default_result/1_total_hash_function.csv'

    return_html_lines = get_html_lines(my_path)

    # Strip JS comments so commented-out functions are not counted
    return_html_lines = _strip_js_comments_from_lines(return_html_lines)

    function_count = 0


    
    modified_lines = []
    hash_function_box = []
    line_count = 0
    for line in return_html_lines:
        potential_box = []
        
        matches_patterns = function_pattern.findall(line)
        
       
        store_changed_line = ''
        store_changed_line = line

        if function_pattern.search(line):   
                
                try:
                    for function_count_one_line in range(len(matches_patterns)):
                        function_count += 1
                        #print(function_count_one_line)
                        if  function_count_one_line == 0:
                            parts = re.split(function_pattern, line, maxsplit=1)
                            #print("line:",line)
                            #print(type(parts[-1]))
                            #print("")
                            after_function_line = ''
                            previous_after_function_line = ''
                            for index_parts in range(2, len(parts)):
                                after_function_line = after_function_line + parts[index_parts]
                            
                            #print(after_function_line)
                            #print("")

                            #after_function_line = parts[-1]
                            
                        else:
                            parts = re.split(function_pattern, after_function_line, maxsplit=1)
                            #print("line:",line)
                            #print(type(parts[-1]))
                            #print("")
                            previous_after_function_line = after_function_line
                            after_function_line = ''
                            for index_parts in range(2, len(parts)):
                                after_function_line = after_function_line + parts[index_parts]
                            
                            after_function_line = parts[-1]
                


                        last_function_line,return_function_text, return_one_line_flag = get_last_line_col(return_html_lines[line_count+1:],after_function_line)   
                        last_line = last_function_line + line_count
                        no_remove_whitespace_text_ = return_function_text
                        return_function_text = remove_whitespace(return_function_text)
                        return_hash = get_hash(return_function_text, no_remove_whitespace_text_)
                        total_hash_function_dict[return_hash] = return_function_text
                        #print(line_count,last_line)
                        box = []
                        box.append(return_hash)
                        box.append(return_function_text)
                        hash_function_box.append(box)
                        #print(return_hash)
                        #print(return_function_text)
                        #print("$$$$$$$$$$$$$$$$$$$$")
                        console_phrase = 'console.log("default_function_in_html: '+ str(return_hash) + '");'
                        #print(console_phrase)
                        split_lines = line.split(after_function_line)
                        if len(matches_patterns) == 1:
                            if return_one_line_flag:
                                store_changed_line = split_lines[0] +   console_phrase + after_function_line
                            else:
                                store_changed_line = store_changed_line + console_phrase

                        else:
                            if function_count_one_line == 0:
                                
                                potential_box.append(split_lines[0])
                                potential_box.append(console_phrase)
                                potential_box.append(after_function_line)
                            else:
                                if return_one_line_flag:
                                    #print("prvious: ", previous_after_function_line)
                                    split_lines = previous_after_function_line.split(after_function_line)
                                    potential_box = potential_box[:-1]
                                    potential_box.append(split_lines[0])
                                    potential_box.append(console_phrase)
                                    potential_box.append(after_function_line)

                                           
                                else:
                                    potential_box.append(console_phrase)
                                    pass
                    
                        #print('Potential box: ',potential_box)

                except Exception as error:
                    print(error)
                    print(my_path)
                    #print(line)
                
            #print(line)

        if len(potential_box) > 0:
            store_changed_line = ''
            for index_potential_box in potential_box:
                store_changed_line += index_potential_box
        
        modified_lines.append(store_changed_line)
        line_count += 1

    '''
    File = open(save_total_hash_function_path, 'w', newline = '')
    wr = csv.writer(File)
    for index in hash_function_box:
        box = []
        box.append(index[0])
        box.append(index[1])
        wr.writerow(box)
    File.close()
    '''
    with open(save_file_path, 'w', encoding = 'utf-8') as saveFile:
        saveFile.writelines(modified_lines)

    html_beautify_execution(save_file_path)
    
    '''
    save_function_hash_file_path = save_file_root + '/hash_function.csv'
    File = open(save_function_hash_file_path, 'w', newline = '')
    wr = csv.writer(File)
    for k,v in total_hash_function_dict.items():
        box = []
        box.append(k)
        box.append(v)
        wr.writerow(box)
    File.close()
    '''
    return function_count, save_file_path





def count_js_function_for_external_js(my_path):
    total_hash_function_dict = {}
    #function_pattern = re.compile(r'\bfunction\b\s*(\w*\s*)?\(\s*.*?\s*\)\s*{')
    function_pattern = re.compile(r'\bfunction\b\s*([^\s(]*\s*)?\(\s*.*?\s*\)\s*{')
    comment_pattern = re.compile(r'//\s*\bfunction\b')
    valid_function1 = re.compile(r'"([^"]*\bfunction\b\s*([^\s(]*\s*)?\(\s*.*?\s*\)\s*{[^"]*)"') 
    split_my_path = my_path.split('/')
    save_file_root = ''

    for index in range(len(split_my_path)-1):
        save_file_root += '/' + split_my_path[index]

    #save_file_path = save_file_root + '/index.html'
    #save_total_hash_function_path = save_file_root + '/default_result/1_total_hash_function.csv'
    
    

    # save hash
    #save_file_hash_body = save_file_root
    #save_file_hash_body = save_file_hash_body.replace('/file_desktop_console','')
    #save_hash_body_path = save_file_hash_body  + '/hash_body_folder'
    #os.makedirs(save_hash_body_path, exist_ok=True)
    # save hash

    #if os.path.exists(save_hash_body_path):
    #    pass
    #else:
    #    result = subprocess.run(['mkdir', save_hash_body_path], capture_output = True, text = True, check = True)
    #print(save_file_path)

    return_html_lines = get_html_lines(my_path)
    function_count = 0



    modified_lines = []
    hash_function_box = []
    line_count = 0
    for line in return_html_lines:
        potential_box = []

        matches_patterns = function_pattern.findall(line)


        store_changed_line = ''
        store_changed_line = line

        if function_pattern.search(line):
            if comment_pattern.search(line):
                pass
            elif valid_function1.search(line): 
                pass
            else:

                try:
                    for function_count_one_line in range(len(matches_patterns)):
                        function_count += 1
                        #print(function_count_one_line)
                        if  function_count_one_line == 0:
                            parts = re.split(function_pattern, line, maxsplit=1)
                            after_function_line = ''
                            previous_after_function_line = ''
                            for index_parts in range(2, len(parts)):
                                after_function_line = after_function_line + parts[index_parts]
                        else:
                            parts = re.split(function_pattern, after_function_line, maxsplit=1)
                            previous_after_function_line = after_function_line
                            after_function_line = ''
                            for index_parts in range(2, len(parts)):
                                after_function_line = after_function_line + parts[index_parts]

                            after_function_line = parts[-1]



                        last_function_line,return_function_text, return_one_line_flag = get_last_line_col(return_html_lines[line_count+1:],after_function_line)
                        last_line = last_function_line + line_count
                        no_remove_whitespace_text_ = return_function_text
                        return_function_text = remove_whitespace(return_function_text)
                        return_hash = get_hash(return_function_text, no_remove_whitespace_text_)
                        total_hash_function_dict[return_hash] = return_function_text
                        box = []
                        box.append(return_hash)
                        box.append(return_function_text)
                        hash_function_box.append(box)
                        console_phrase = 'console.log("default_function_in_ext_js: '+ str(return_hash) + '");'
                        split_lines = line.split(after_function_line)
                        if len(matches_patterns) == 1:
                            if return_one_line_flag:
                                store_changed_line = split_lines[0] +   console_phrase + after_function_line
                            else:
                                store_changed_line = store_changed_line + console_phrase

                        else:
                            if function_count_one_line == 0:

                                potential_box.append(split_lines[0])
                                potential_box.append(console_phrase)
                                potential_box.append(after_function_line)
                            else:
                                if return_one_line_flag:
                                    split_lines = previous_after_function_line.split(after_function_line)
                                    potential_box = potential_box[:-1]
                                    potential_box.append(split_lines[0])
                                    potential_box.append(console_phrase)
                                    potential_box.append(after_function_line)


                                else:
                                    potential_box.append(console_phrase)
                                    pass
                except Exception as error:
                    print(error)
                    print(my_path)
                    #print(line)

            #print(line)

        if len(potential_box) > 0:
            store_changed_line = ''
            for index_potential_box in potential_box:
                store_changed_line += index_potential_box

        modified_lines.append(store_changed_line)
        line_count += 1
    with open(my_path, 'w', encoding = 'utf-8') as saveFile:
        saveFile.writelines(modified_lines)

    js_beautify_execution(my_path)
    

def js_beautify_execution(my_js_path):
    try:
        result = subprocess.run(['js-beautify', '-r', my_js_path], capture_output = True, text = True, check = True)
    except:
        print("NOOOOOO JS BEAUTIFY EXE ERORORORORORORO!!!!!")

def html_beautify_execution(my_html_path):
    result = subprocess.run(['html-beautify', '-r', my_html_path], capture_output = True, text = True, check = True)

    #print(result)

def mkdir_default_result(my_html_path):
    split_html_path = my_html_path.split('/')
    folder_path = ''

    for index in range(len(split_html_path)-1):
        folder_path += '/' + split_html_path[index]
    js_folder_path = folder_path + '/file_desktop_console'
    folder_path = folder_path + '/default_result'
    if os.path.exists(folder_path):
        pass
    else:
        result = subprocess.run(['mkdir', folder_path], capture_output = True, text = True, check = True)
    
    
    if os.path.exists(js_folder_path):
        pass
    else:
        result = subprocess.run(['mkdir', js_folder_path], capture_output = True, text = True, check = True)
def execute_external_js(my_html_path):
    #print(my_html_path)
    node_script_path = str(Path(__file__).resolve().parent / "1_get_console_log.js")
    if os.path.exists(node_script_path):
        #print(f"Executing JS on: {node_script_path}")
        result = subprocess.run(['node', node_script_path, my_html_path],capture_output =True, text= True)
    else:
        print("Error: JS file does not exist")
    
    #time.sleep(3)
    #print(result)


def execute_external_python(my_html_path):
    python_path = str(Path(__file__).resolve().parent / "2_esprima_total_function.py")
    if os.path.exists(python_path):
        #print(f"Executing python on: {python_path}")
        result = subprocess.run(['python3', python_path, my_html_path],capture_output =True, text= True)
        #print('total_function from esprima: ',result.stdout)
    else:
        pass
        #print("Error: Python file does not exist")





def get_external_js_path(my_path):
    html_name = os.path.basename(my_path)
    html_name = '/' + html_name
    apwg_path = my_path.replace(html_name ,'')
    file_desk_name = os.path.join(apwg_path, 'files-desktop')
    copy_desk_name = os.path.join(apwg_path, 'file_desktop_console' )

    #for source in os.listdir(file_desk_name):
    #    #folder_name = os.path.basename(source)
    #    destination = os.path.join(copy_desk_name, source)
    #    source_path = os.path.join(file_desk_name, source)
    #    shutil.copytree(source_path, destination, dirs_exist_ok=True)
    #    print(f"Copied {source} to {destination}")
    shutil.copytree(file_desk_name, copy_desk_name , dirs_exist_ok=True)
    js_path_box = []
    for index in os.listdir(copy_desk_name):
        if index[-3:] == '.js' or '.js?' in index:
            js_path_box.append(os.path.join( copy_desk_name, index))
    return js_path_box



def chagne_files_name(my_js_path):
    js_name = os.path.basename(my_js_path)
    js_name = '/' + js_name
    files_desktop = my_js_path.replace(js_name, '')
    original_files_desktop = files_desktop.replace('file_desktop_console','files-desktop')
    
    change_files_desktop = original_files_desktop
    change_original_files_desktop = original_files_desktop.replace('files-desktop', 'original-files-desktop')
    #print(files_desktop, original_files_desktop)
    #print(change_files_desktop, change_original_files_desktop)

    result = subprocess.run(['mv', original_files_desktop, change_original_files_desktop], capture_output = True, text = True, check = True)
    result = subprocess.run(['mv', files_desktop, change_files_desktop], capture_output = True, text = True, check = True)



def get_total_path(input_path):
    apwg_lists = os.listdir(input_path)
    
    total_html_path = []
    count = 0
    t_count = 0
    print(len(apwg_lists))
    for index in apwg_lists:
        apw_path_ = os.path.join(input_path, index)
        html_path = os.path.join(apw_path_, 'index-desktop.html')
        t_count += 1
        if t_count % 10000 == 0:
            print("total: ", t_count)
            #print("exist: ", count )
            #print("exist file: ", len(total_html_path))
        added_console_path = os.path.join(apw_path_, 'added_console_index.html')
        if os.path.exists(added_console_path):
            count += 1
            trash = 0
        else:
            #html_path = os.path.join(apw_path_, 'index.html')
            total_html_path.append(html_path)
        #total_html_path.append(html_path)
    print(f"Total: {len(apwg_lists)}")
    print(f"Exists: {count}")
    print(f"Remain: {len(total_html_path)}")
    return total_html_path




def get_total_path_apwg_dataset(input_path):
    #apwg_lists = os.listdir(input_path)
    
    apwg_lists = []

    for month_index in os.listdir(input_path):
        month_path_ = os.path.join(input_path, month_index)

        for day_index in os.listdir(month_path_):
            day_path_ = os.path.join(month_path_, day_index)

            for apwg_index in os.listdir(day_path_):
                apwg_path_ = os.path.join(day_path_, apwg_index)
                apwg_lists.append(apwg_path_)
    total_html_path = []
    count = 0
    t_count = 0
    no_index_count = 0
    print(len(apwg_lists))
    for index in apwg_lists:
        apw_path_ = os.path.join(input_path, index)
        html_path = os.path.join(apw_path_, 'index-desktop.html')
        t_count += 1
        
        if not os.path.exists(html_path):
            no_index_count += 1
            continue


        if t_count % 10000 == 0:
            print("total: ", t_count)
            #print("exist: ", count )
            #print("exist file: ", len(total_html_path))
        added_console_path = os.path.join(apw_path_, 'added_console_index.html')
        if os.path.exists(added_console_path):
            count += 1
            trash = 0
        else:
            #html_path = os.path.join(apw_path_, 'index.html')
            total_html_path.append(html_path)
        #total_html_path.append(html_path)
    print(f"Total: {len(apwg_lists)}")
    print(f"Exists: {count}")
    print(f"No Index : {no_index_count}")
    print(f"Remain: {len(total_html_path)}")
    return total_html_path




def _strip_js_comments_from_lines(lines):
    """Remove single-line (//) and multi-line (/* */) JS comments from source
    lines while preserving string literals and line count.

    Returns a new list of lines with comments replaced by whitespace.
    """
    code = ''.join(lines)
    result_chars = []
    i = 0
    n = len(code)
    while i < n:
        c = code[i]
        # String literals -- pass through unchanged
        if c in ('"', "'", '`'):
            quote = c
            result_chars.append(c)
            i += 1
            while i < n:
                ch = code[i]
                result_chars.append(ch)
                if ch == '\\' and i + 1 < n:
                    result_chars.append(code[i + 1])
                    i += 2
                    continue
                if ch == quote:
                    i += 1
                    break
                i += 1
            continue
        # Single-line comment
        if c == '/' and i + 1 < n and code[i + 1] == '/':
            while i < n and code[i] != '\n':
                i += 1
            result_chars.append('\n')
            continue
        # Multi-line comment
        if c == '/' and i + 1 < n and code[i + 1] == '*':
            i += 2
            while i + 1 < n and not (code[i] == '*' and code[i + 1] == '/'):
                if code[i] == '\n':
                    result_chars.append('\n')
                i += 1
            i += 2  # skip */
            continue
        result_chars.append(c)
        i += 1
    cleaned = ''.join(result_chars)
    return cleaned.splitlines(keepends=True)


def extract_hashes_from_file(file_path):
    """Extract JS function bodies from a single file, hash them,
    and save to hash_db.  Read-only: never modifies the original file.
    """
    function_pattern = re.compile(r'\bfunction\b\s*([^\s(]*\s*)?\(\s*.*?\s*\)\s*\{')

    try:
        raw_lines = get_html_lines(file_path)
    except Exception:
        return 0

    # Strip JS comments so that commented-out functions are not hashed
    lines = _strip_js_comments_from_lines(raw_lines)

    count = 0
    line_count = 0
    for line in lines:
        if function_pattern.search(line):
            matches = function_pattern.findall(line)
            try:
                after = ''
                for mi in range(len(matches)):
                    if mi == 0:
                        parts = re.split(function_pattern, line, maxsplit=1)
                        after = ''
                        for pi in range(2, len(parts)):
                            after += parts[pi]
                    else:
                        parts = re.split(function_pattern, after, maxsplit=1)
                        after = ''
                        for pi in range(2, len(parts)):
                            after += parts[pi]

                    last_line, func_text, _ = get_last_line_col(
                        lines[line_count + 1:], after)
                    norm_text = remove_whitespace(func_text)
                    get_hash(norm_text, func_text)
                    count += 1
            except Exception:
                pass
        line_count += 1
    return count


def main(my_lists):
    """Process a chunk of files: extract JS function hashes.
    Read-only -- never writes to the dataset directory.
    """
    for file_path in my_lists:
        try:
            # 1) Hash functions in the HTML/PHP file itself
            extract_hashes_from_file(file_path)

            # 2) Find .js files in the same directory and hash those too
            parent_dir = os.path.dirname(file_path)
            for f in os.listdir(parent_dir):
                if f.lower().endswith('.js'):
                    js_path = os.path.join(parent_dir, f)
                    extract_hashes_from_file(js_path)
        except Exception as e:
            print("[WARN] %s : %s" % (file_path, e))


def multi_process_func(my_list):
    
    pool = multiprocessing.Pool()
    chunk_size = 100 # 100
    chunks = [my_list[i:i + chunk_size] for i in range(0, len(my_list), chunk_size)]
    print(len(chunks))
    pool.map(main, chunks)
    print("finish!!!!!!!!!!!!!!!!!!!!")



def discover_html_files(dataset_root):
    """Recursively find ALL .html and .php files under dataset_root.

    Returns a list of absolute paths.
    """
    target_extensions = ('.html', '.htm', '.php', '.phtml')
    html_files = []
    for dirpath, _dirnames, filenames in os.walk(dataset_root):
        for f in sorted(filenames):
            if f.lower().endswith(target_extensions):
                html_files.append(os.path.join(dirpath, f))
    return html_files


if __name__ == "__main__":
    import argparse as ap
    p = ap.ArgumentParser(description="Build JS function hash DB from phishing kit dataset")
    p.add_argument("--dataset", required=True,
                   help="Root directory of phishing kit dataset (e.g. /path/to/phishing_kits)")
    p.add_argument("--hash-db", required=True,
                   help="Output directory for hash files (e.g. ./results/hash_db)")
    p.add_argument("--num", type=int, default=0,
                   help="Max number of files to process (0 = all)")
    p.add_argument("--csv-out", default="",
                   help="Optional: path to save CSV list of discovered HTML files")
    cli = p.parse_args()

    global save_total_hash_path_
    global no_crash_total_hash_path_

    # --- Output directories ---
    save_total_hash_path_ = cli.hash_db
    no_crash_total_hash_path_ = cli.hash_db
    os.makedirs(save_total_hash_path_, exist_ok=True)

    # --- Discover HTML files ---
    print("[HashDB] Scanning dataset: %s" % cli.dataset)
    return_total_html_path = discover_html_files(cli.dataset)
    print("[HashDB] Found %d files total" % len(return_total_html_path))

    if cli.num > 0:
        return_total_html_path = return_total_html_path[:cli.num]
        print("[HashDB] Processing first %d files (--num %d)" % (len(return_total_html_path), cli.num))

    # --- Optional CSV ---
    if cli.csv_out:
        with open(cli.csv_out, 'w', newline='') as f:
            wr = csv.writer(f)
            for idx in return_total_html_path:
                wr.writerow([idx])
        print("[HashDB] Saved HTML list to %s" % cli.csv_out)

    # --- Process ---
    print("[HashDB] Starting hash extraction (multiprocessing)...")
    multi_process_func(return_total_html_path)
    print("[HashDB] Done! Hash files saved to: %s" % cli.hash_db)
    #count = 0

    
    '''
    for index_html in return_total_html_path:
        if count % 100 == 0:
            print(count)
            print(index_html)
        #print(count, index_html)


        # step 1 -> normalize the html files
        step_flag = True
        try:
            html_beautify_execution(index_html)
        except Exception as e:
            step_flag = False
            print("html beautify execution error : ", Exception)



        

        if step_flag:

            # step 2 -> mkdir default_result
            mkdir_default_result(index_html)

            # step 3 -> find all js functions and add console.log
            result_function_count, added_html_path = count_js_function(index_html)
            #print('total_function from regex: ', result_function_count)
            return_js_path = get_external_js_path(index_html)
            #print(return_js_path)
            if len(return_js_path) > 0:
                for ex_js_index in return_js_path:
                    js_beautify_execution(ex_js_index)
                    count_js_function_for_external_js(ex_js_index)
                chagne_files_name(return_js_path[0])
            else:
                trash = 0

            # step 4 -> execute 1_get_console_log.js
            #execute_external_js(added_html_path)


            # step 5 -> execute 2_esprima_function.py  # In this prcoess, it has to use original html file to do double check!!!
            #execute_external_python(index_html)

            count += 1

        #break        




    '''
