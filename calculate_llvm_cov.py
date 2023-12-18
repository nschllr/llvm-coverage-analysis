#!/bin/python3.10

# Fuzzing with afl instrumented binary
# coverage analysis with llvm instrumented binary
# --> compile with:
# clang++ -fprofile-instr-generate -fcoverage-mapping foo.cc -o foo

# directory structure:
# AFL++:
#   afl_out/afl_TRIAL_NUM/default/queue
#
# Sileo:
#   afl_out/sileo_TRIAL_NUM/%SILEO_MODE%/%TARGET%/worker_0/run_NUM/{default/queue, default/fuzzer_stats}
#

import traceback
from argparse import ArgumentParser, Namespace
from collections import defaultdict
from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
import shutil
import concurrent.futures
import concurrent.futures.thread
import tempfile
import threading
from typing import Any, Dict, List, Optional, Sequence
import re
import time
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
from matplotlib import rcParams
import numpy as np
import subprocess
import hashlib
from natsort import natsorted
import random

CONTAINER_NAME = "llvm_cov_analysis"
skip_corpus = False
mode = ""
show_bands = False
regex = ""


def get_testcases(corpus_path: Path) -> list[Path]:
    print(f"Gathering testcases from {corpus_path.as_posix()}")
    testcases = sorted(list(corpus_path.glob("id:*")))
    return testcases

def get_starttime(fuzzer_stats_path : Path) -> str:
    with open(fuzzer_stats_path, "r") as fd:
        lines: list[str] = fd.readlines()

    starttime = ""
    if len(lines) > 0:
        for line in lines:
            if "start_time" in line:
                starttime: str = line.split(":")[1].strip()
                #print(f"starttime: {starttime}")
                return starttime      
    
    print("No or empty fuzzer_stats, using start_time.txt!")
    start_time_file : Path = fuzzer_stats_path.parent.parent / "start_time.txt"
    if start_time_file.exists():
        with open(start_time_file.as_posix(),"r") as fd:
            starttime = fd.readline().split(".")[0]
        if starttime != "":
            return starttime
        else:
            print(f"Error: no starttime found -- {fuzzer_stats_path} / {start_time_file}")
    return ""

def get_afl_version(fuzzer_stats_path : Path) -> str:
    with open(fuzzer_stats_path, "r") as fd:
        lines: list[str] = fd.readlines()

    afl_version = ""
    if len(lines) > 0:
        for line in lines:
            if "afl_version" in line:
                afl_version: str = line.split(":")[1].strip()
                #print(f"starttime: {starttime}")
                return afl_version

    print(f"No version found! -- {fuzzer_stats_path}")
    return ""

def check_legacy_afl(afl_version : str) -> bool:

    # for afl++ versions
    if "++" in afl_version:
        re_match: re.Match[str] | None = re.search("[0-9]*\.[0-9]*", afl_version)
        if re_match is not None:
            stripped_version : float = float(re_match.group(0))
            if stripped_version > 2.52:
                return False
        else:
            # this shouldn't happen 
            print(f"#### RE MATCH is None!! --> afl_version: {afl_version} ########")
            return True
    return True



def get_testcase_cov_time(testcase : Path, starttime : str, afl_version : str) -> int:
    return 0


def get_all_fuzzer(working_args, cstrip = ""):
    corpus_base_path = working_args["corpus_path"]
    all_fuzzers : list[Path] = natsorted(list(corpus_base_path.iterdir()))
    fuzzer_names : list = sorted(list(set(match.group(0).strip(cstrip) for fuzzer_entry in all_fuzzers if (match := re.search(regex, fuzzer_entry.name)) is not None)))

    return fuzzer_names

def mount_corpus(working_args, base_dir : Path, fuzzer_name: str, umount = False) -> None:
    
    corpus_base_path = working_args["corpus_path"]
    trial_paths : list[Path] = list(corpus_base_path.glob(f"*{fuzzer_name}*"))
    
    if len(trial_paths) == 0:
        # fuzzbench trials
        print("Found fuzzbench trials")
        trial_paths : list[Path] = list(corpus_base_path.glob(f"trial*"))

    for trial_id, trial_path in enumerate(trial_paths):
        
        
        dest_path = Path(base_dir / "tmp" / "full_corpus" / f"trial_{trial_id}")
        if not umount:
            print(f"creating trial: trial_{trial_id}")
            (base_dir / "tmp" / "full_corpus" / f"trial_{trial_id}").mkdir(exist_ok=True)
            (base_dir / "profraw_files" / f"trial_{trial_id}").mkdir(exist_ok=True, parents=True)
            (base_dir / "profdata_files" / f"trial_{trial_id}").mkdir(exist_ok=True, parents=True)
            res = subprocess.run(["sudo", "mount", "-r", "-B", "-v", trial_path.as_posix() + "/", dest_path])
        else:
            res = subprocess.run(["sudo", "umount", "-v", dest_path])

def extract_timestamp(file_path : Path) -> int:
    # Extract the timestamp from the file name
    timestamp_str = file_path.name.split("_ts:")[1].split(".")[0]
    return int(timestamp_str)

def group_files_by_minute(files : list[Path]):
    # Group files based on the minute part of the timestamp
    file_groups = defaultdict(list)
    for file in files:
        timestamp = extract_timestamp(file)
        minute = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M') # type: ignore
        file_groups[minute].append(file)
    return file_groups

def calculate_cov_branches(json_data):
    def traverse(item, func):
        func(item)
        if not isinstance(item, str) and (isinstance(item, list) or isinstance(item, tuple)):
            for subitem in item:
                traverse(subitem, func)
        elif isinstance(item, dict):
            for subitem in item.items():
                traverse(subitem, func)

    st = set()

    def add_st(item):
        if isinstance(item, dict) and 'branches' in item and isinstance(item['branches'], list):
            for br in item['branches']:
                rep_br = tuple(br[:4] + br[6:])
                if br[4] > 0:
                    st.add((rep_br, True))
                if br[5] > 0:
                    st.add((rep_br, False))

    traverse(json_data, add_st)
    return len(st)

def llvm_cov(working_args, trial: str, base_dir: Path) -> tuple[bool, Path]:

    trial = f"trial_{trial}"
    full_corpus : Path = base_dir / "tmp" / "full_corpus"
    profraw_dir : Path = base_dir / "profraw_files" / trial
    profdata_dir : Path = base_dir / "profdata_files" / trial
    target_bin = working_args["cov_bin"]
    target_args = working_args["target_args"]
    clean_up(profdata_dir, create = True)

    print("Starting llvm coverage analysis")

    testcases_to_starttime: list[tuple] = []
    starttime = ""
    testcases = []

    queue_dirs : list[Path] = natsorted(list(Path(full_corpus / trial).glob("**/queue")))
    fuzzer_stats_paths : list[Path] = natsorted(list(Path(full_corpus / trial).glob("**/fuzzer_stats")))

    # there should be the same amount of fuzzer_stats files as queue_dirs otherwise, something is wrong
    assert len(queue_dirs) > 0, f"Found no queue dirs: {len(queue_dirs)} -- {queue_dirs} "
    assert len(fuzzer_stats_paths) > 0, f"Found no queue dirs: {len(fuzzer_stats_paths)} -- {fuzzer_stats_paths} "

    if len(queue_dirs) != len(fuzzer_stats_paths):
        print(f"Found a different amount of fuzzer_stats files and queue directorys: Queues: {len(queue_dirs)} -- stats: {len(fuzzer_stats_paths)}")
        assert len(queue_dirs) == len(fuzzer_stats_paths), "different len of queue and fuzzer_stats"

    legacy_afl : bool | None = None

    for queue_dir, fuzzer_stats in zip(queue_dirs, fuzzer_stats_paths):
        testcases: list[Path] = get_testcases(queue_dir)
        starttime: str = get_starttime(fuzzer_stats)
        afl_version: str = get_afl_version(fuzzer_stats)

        # asume that all queues of the fuzzer have the same afl version -- so the first one will do it
        if legacy_afl is None:
            legacy_afl = check_legacy_afl(afl_version)

        testcases_to_starttime.extend(list(zip([afl_version] * len(testcases), [starttime] * len(testcases), testcases)))

    print(f"Generating profraw data from testcases... ({trial} - {base_dir.name})")
    cov_times = []

    for i, testcase_to_starttime in enumerate(testcases_to_starttime):
        afl_version, starttime, testcase = testcase_to_starttime

        if i % 1000 == 0:
            print(f"Processing Testcase {trial} - {base_dir.name}:\t {i}/{len(testcases_to_starttime)}")

        cov_time: int = 0

        if legacy_afl:
            testcase_time = int(os.stat(testcase).st_mtime)
            cov_time = testcase_time
        else:
            # some afl++ version did not assign a time to "orig:" testcases
            if "time" not in testcase.name:
                testcase_time = 0
            else:
                testcase_time = testcase.name.split(",time:")[1].split(",")[0]
            cov_time = int(starttime) + int(testcase_time) // 1000
        cov_times.append(cov_time)
        profraw_file = f"{profraw_dir}/llvm_{i:08d}_ts:{cov_time}.profraw"
        # print(f"profraw_file:",profraw_file)
        os.environ["LLVM_PROFILE_FILE"] = profraw_file

        target_args_w_input = target_args

        while "@@" in target_args_w_input:
            target_args_w_input = target_args_w_input.replace("@@", str(testcase))
        #llvm_target_cmd = f"{target_bin} {target_args} {testcase}"
        llvm_target_cmd = f"{target_bin} {target_args_w_input}"

        execute_cmd(llvm_target_cmd.split(" "))
    print(f"\nGenerating profraw files done ({trial} - {base_dir.name})!")

    profraw_files : list[Path] = sorted(list(profraw_dir.iterdir()))
    clean_up(profdata_dir, create = True)

    file_groups = group_files_by_minute(profraw_files)

    print("Start multiprocessed merging by minute")
    with concurrent.futures.ProcessPoolExecutor() as executor:
        futures = []
        for minute, files in file_groups.items():
            # merge_by_minute_single(files, minute, trial)
            futures.append(executor.submit(merge_by_minute_single, files, minute, trial))
        concurrent.futures.wait(futures)

    print(f"Merging and exporting data profdata... ({trial} - {base_dir.name})")

    profdata_files : list[Path] = sorted(list(profdata_dir.iterdir()))
    timestamp_to_b_covered : list[tuple]= []
    profdata_file_final: Path = profdata_dir / f"llvm-final.profdata"

    for id, profdata_file in enumerate(profdata_files):
        if not profdata_file.name.endswith("profdata"):
            continue

        timestamp = extract_timestamp(profdata_file)
        if profdata_file_final.exists():
            llvm_profdata_cmd: str = f"llvm-profdata-14 merge -sparse {profdata_file} {profdata_file_final} -o {profdata_file_final}"
        else:
            llvm_profdata_cmd: str = f"llvm-profdata-14 merge -sparse {profdata_file} -o {profdata_file_final}"

        #print(f"Running command ({trial} - {base_dir.name}): {llvm_profdata_cmd}")
        print(f"Processing (merge profdata) ({trial} - {base_dir.name}): {id}/{len(profdata_files)} -- {round(id / len(profdata_files)*100,2)}%")
        
        execute_cmd(llvm_profdata_cmd.split(" "), check = True)
        llvm_export_cmd = f"llvm-cov-14 export -format=text -region-coverage-gt=0 -skip-expansions {target_bin} -instr-profile={profdata_file_final}"
        #print(f"Running export command ({trial} - {base_dir.name}): {llvm_export_cmd}")
        res = execute_cmd(llvm_export_cmd.split(" "), capture_output=True)
        report_data = json.loads(res.stdout)
        
        branch_count = calculate_cov_branches(report_data["data"][0]["files"])
        #branch_count = get_branches_covered(report_data)
        
        timestamp_to_b_covered.append((timestamp, branch_count))

        result_dir : Path = base_dir / "results" / trial
        result_dir.mkdir(exist_ok=True, parents=True)

        with open(f"{result_dir}/timestamp_to_b_covered.txt","a") as fd:
                fd.write(f"{timestamp},{branch_count}\n")

        #with open(f"{profdata_dir}/report_{timestamp}.json","a") as fd:
        #        fd.write(report_data)

        if len(res.stderr) > 0:
            print(f"Seems an error occured, see {profdata_dir}/llvm-cov.stderr for more information")
            with open(f"{profdata_dir}/llvm-cov.stderr", "wb") as fd:
                fd.write(res.stderr)
        with open(f"{profdata_dir}/llvm-cov.json", "wb") as fd:
            fd.write(res.stdout)

        profdata_file.unlink()
    print(f"Export done ({trial} - {base_dir.name})")

    # cleanup to save space
    clean_up(profraw_dir)
    #clean_up(full_corpus)

    return True, base_dir

def get_crashes(base_dir : Path):
    print("     Get crashes...")
    full_corpus : Path = base_dir / "tmp" / "full_corpus"
    print(full_corpus)
    crash_dirs : list = list(full_corpus.glob("**/crashes/"))
    crashes : list[Path] = []
    print(f"Number of crash dirs: {len(crash_dirs)}")

    for crash_dir in crash_dirs:
        crashes.extend(get_testcases(crash_dir))
    print(f"found crashes: {len(crashes)}")

    hashes : list[str] = []
    hashed_crashes : list[Path] = []
    ts_to_crash : list[tuple] = []

    for crash in crashes:
        crash_hash = get_hash(crash)

        if crash_hash not in hashes:
            hashed_crashes.append(crash)
            hashes.append(crash_hash)
        else:
            continue

        print(f"{len(hashed_crashes)} crashes found!")
        crash_fs_path : Path = list(crash.parent.parent.glob("./**/fuzzer_stats"))[0]
        print(f"found fuzzer_stats for crash: {crash_fs_path}")
        cov_times = []
        starttime = get_starttime(crash_fs_path)
        crash_timestamp = crash.name.split(",time:")[1].split(",")[0]
        ts_to_crash.append((int(starttime) + int(crash_timestamp) // 1000,crash))

    return ts_to_crash


def get_hash(file: Path) -> str:
    with open(file, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()

def merge_by_minute_single(files : list[Path], minute, trial):
    timestamp = int(datetime.strptime(minute, '%Y-%m-%d %H:%M').timestamp())
    print(f"Merging data for timestamp ({trial}): {minute} --- \t{len(files)} files")

    profdata_dir = files[0].parent.parent.parent / "profdata_files" / trial
    # temporary save files
    fd, profdata_save_file = tempfile.mkstemp(dir=profdata_dir, prefix="llvm_tmp_", suffix=".txt")
    with open(profdata_save_file, "w") as fd:
        for profdata_file in files:
            fd.write(f"{profdata_file}\n")

    new_profdata_file: str = f"{profdata_dir}/llvm_ts:{timestamp}.profdata"
    llvm_profdata_cmd: str = f"llvm-profdata-14 merge -sparse -f {profdata_save_file} -o {new_profdata_file}"
    execute_cmd(llvm_profdata_cmd.split(" "), check=True)

    # deleting old files
    for profdata_file in files:
        profdata_file.unlink()
    Path(profdata_save_file).unlink()

def clean_up(dir_path : Path, create : bool = False):
    print(f"Cleaning up: {dir_path}")
    if dir_path.exists():
        shutil.rmtree(dir_path)

    if create:
        dir_path.mkdir(parents=True)

def execute_cmd(cmd : List[str], capture_output=True, check = False):
    #print(f"command: " + " ".join(cmd))
    res = subprocess.run(list(filter(None, cmd)), capture_output=capture_output, check=check)

    return res


def plot_time_to_branch():
    pass


def get_branches_covered(json_data) -> int:
    return int(json_data["data"][0]["totals"]["branches"]["covered"])


def get_results(base_dir):
    import statistics

    print(f"Get results: {base_dir.name}")
    json_data_paths : list[Path] = list(base_dir.glob("profdata_files/**/llvm-cov.json"))
    print("json data paths:", json_data_paths)
    branches = []
    functions = []

    for json_file in json_data_paths:
        json_data = None
        with open(json_file.as_posix(), "r") as fd:
            json_data = json.load(fd)
        
        branches.append(json_data["data"][0]["totals"]["branches"])
        functions.append(json_data["data"][0]["totals"]["functions"])

    b_perc = []
    b_covered = []
    f_perc = []
    b_count = 0
    for b_info in branches:
        b_count = b_info["count"]
        b_perc.append(b_info["percent"])
        b_covered.append(b_info["covered"])
    for f_info in functions:
        f_perc.append(f_info["percent"])

    print(f"Branch coverage median (branches): {statistics.median(b_covered)} / {b_count}")
    print(f"Branch coverage median (percent): {statistics.median(b_perc)}%")
    print(f"Function coverage median: {statistics.median(f_perc)}%")

def get_a_clean_dir(dir_path : Path, remove: bool = True):
    print(f"Init directory structure: {dir_path}")
    if dir_path.exists() and remove:
        shutil.rmtree(dir_path)
    dir_path.mkdir(parents=True,exist_ok=True)
    return dir_path

def create_directory_structure(base_dir: Path, skip_corpus = False):

    tmp_dir : Path = base_dir / "tmp"
    tmp_corpus_dir : Path  = tmp_dir  / "full_corpus"
    profraw_dir = base_dir / "profraw_files"
    results_dir : Path = base_dir / "results"

    if skip_corpus and not tmp_corpus_dir.exists():
        print(f"it seems you want to skip the corpus copy, but there is no corpus at {tmp_corpus_dir}")
        exit()

    get_a_clean_dir(profraw_dir)
    get_a_clean_dir(results_dir)

    get_a_clean_dir(tmp_corpus_dir,  not skip_corpus)


def gen_arguments(args : Namespace) -> dict[str,Any]:
    mode : bool = args.mode

    if args.corpus is None and args.calc:
        print("No corpus path given. Exiting")
        exit()
    else:
        corpus_path : Path = args.corpus
    
    if args.cov_bin is None and args.calc:
        print("No coverage binary path given. Exiting")
        exit()
    else:
        if args.cov_bin.exists():
            cov_bin_path : Path = args.cov_bin
        else:
            print("Coverage binary does not exist!")
            exit()
        
    trials : int = args.trials
    target_name : str = args.target

    return {"mode" : mode, "corpus_path": corpus_path, "cov_bin": cov_bin_path, "trials" : trials, "target_name": target_name, "target_args": args.target_args}

def random_rgb_color():
    return tuple(np.random.rand(3,))

def color_difference(color1, color2):
    return sum((c1 - c2) ** 2 for c1, c2 in zip(color1, color2))

def is_color_different(color, used_colors, threshold=0.5):
    for used_color in used_colors:
        if color_difference(color, used_color) < threshold:
            return False
    return True


def calc_plot_data(fuzzer_names : set[str] = set(), img_cnt = 0, fuzzer_colors : dict = {}, base_dir = Path("coverage_analysis"), plot_crashes : bool = False):# -> dict[str, Dict[Any, Any]]:

    if not Path("plots").exists():
        Path("plots").mkdir()    
    
    if not Path("plots/incremental").exists():
        Path("plots/incremental").mkdir()

    used_colors = set()

    if len(fuzzer_names) > 0 and len(fuzzer_colors) == 0:
        for fuzzer_name in fuzzer_names:
            if len(fuzzer_names) < 10:
                fuzzer_color = random.choice(list(mcolors.TABLEAU_COLORS.keys()))
                while fuzzer_color in list(fuzzer_colors.values()):
                    fuzzer_color = random.choice(list(mcolors.TABLEAU_COLORS.keys()))
                fuzzer_colors.update({fuzzer_name:fuzzer_color})
            else:
                for color_idx in range(len(fuzzer_names)): 
                    fuzzer_color = random_rgb_color()    
                    # Check if the color is sufficiently different from used colors
                    while not is_color_different(fuzzer_color, used_colors, threshold=0.5):
                        fuzzer_color = random_rgb_color()
                    fuzzer_colors.update({fuzzer_name:fuzzer_color})

    fig, ax = plt.subplots()

    all_ts_data_paths: list[Path] = sorted(list(base_dir.glob(f"*/results/*/timestamp_to_b_covered.txt")))
    #print(all_ts_data_paths)
    num_trials = len(all_ts_data_paths) // len(fuzzer_names)
    print(f"Number of trials: {num_trials}")
    if len(all_ts_data_paths) == 0:
        print("no timestamp files found yet")
        return {}
    else:
        print(f"Found timestamps")
        
    # print(f"data paths: {all_ts_data_paths}")
    # fuzzer_names = set()
    if len(fuzzer_names) == 0:
        print(f"extract fuzzer name from path with regex: {regex}")
        for ts_data_path in all_ts_data_paths:
            name_match = re.search(regex, ts_data_path.as_posix())
            if name_match != None:
                print(f"name match: {name_match.group(0)}")
                if name_match.group(0) in fuzzer_names:
                    continue
                else:
                    fuzzer_name = name_match.group(0)
                    fuzzer_names.add(fuzzer_name)
                    print(f"found stats for {fuzzer_name}")
            else:
                fuzzer_name = ""
                print(f"no match found for {regex}")
                continue

    fuzzer_to_cov : Dict[str, Dict] = {}

    for fuzzer_name in sorted(fuzzer_names):
        fuzzer_name = fuzzer_name.strip()
        print(f"Processing: {fuzzer_name}")
        # all trial paths of fuzzer with name...
        # coverage_analysis_old/afl/profdata_files/trial_0/timestamp_to_b_covered.txt
        all_trial_paths = sorted(list(base_dir.glob(f"{fuzzer_name}/results/*/timestamp_to_b_covered.txt")))
        ts_to_crash_file: Path = base_dir / fuzzer_name / "results/timestamp_to_crash.txt"

        ts_to_crashes = []
        if ts_to_crash_file.exists() and plot_crashes:
            with open(ts_to_crash_file.as_posix(),"r") as fd:
                ts_to_crashes: list[str] = fd.readlines()

        ts_crash_list: list[int] = []

        for ts_to_crash in ts_to_crashes:
            ts =  ts_to_crash.split(",")[0] 
            # ts_to_crash_dict.update({ts : crash})
            ts_crash_list.append(int(ts))

        trial_results_branches: list[list] = []
        trial_results_ts: list[list] = []

        ts_relative_crash_list = []
        
        for ts_to_branch_file in all_trial_paths:
            ts_to_branch = []
            with open(ts_to_branch_file.as_posix(),"r") as fd:
                ts_to_branch: list[str] = fd.readlines()
            ts_list = []
            branches_covered_list = []
            ts_relative = 0
            for i in range(len(ts_to_branch)):

                ts_to_branch_cov = ts_to_branch[i]
                if i < len(ts_to_branch)-1:
                    ts_to_branch_cov_next = ts_to_branch[i+1]
                else:
                    ts_to_branch_cov_next = ts_to_branch[i]

                ts, branches_covered = ts_to_branch_cov.split(",")
                ts_next, branches_covered_next = ts_to_branch_cov_next.split(",")
                ts = int(ts)
                ts_next = int(ts_next)
                
                while True:
                    if ts in ts_crash_list:
                        #print(f"found {ts} in {ts_crash_list}")
                        ts_relative_crash_list.append(ts_relative)
                        ts_crash_list.remove(ts)
                        
                    if ts + 1 < ts_next:
                        branches_covered_list.append(int(branches_covered))
                        ts_list.append(ts_relative)
                        ts_relative += 1
                        ts += 1
                    else:
                        branches_covered_list.append(int(branches_covered))
                        ts_list.append(ts_relative)
                        ts +=1
                        ts_relative += 1
                        break

            trial_results_branches.append(branches_covered_list)
            trial_results_ts.append(ts_list)

        if len(trial_results_branches) == 0:
            continue
        all_trial_branches = []
        min_num_entries: int = min([len(x) for x in trial_results_branches])
        if min_num_entries < 2:
            continue
        for idx in range(min_num_entries):
            value_series = []
            for trial_idx in range(len(trial_results_branches)):
                value_series.append(trial_results_branches[trial_idx][idx])  
            all_trial_branches.append(value_series)


        lower = []
        upper = []
        plot_bands = False
        try:
            l_perc = int(0.33 * num_trials)
            u_perc = int(0.66 * num_trials) + 1 
            
            #print(f"Calculating percentile: {l_perc} - {u_perc}")
            for values in all_trial_branches:
                d_interval = sorted(values)[l_perc:u_perc]
                min_val = d_interval[0]
                max_val = d_interval[-1]
                lower.append(min_val)
                upper.append(max_val)
                plot_bands = True
        except Exception as e:
            print("Seems not enough values to unpack")
            print(e)
        median = np.median(all_trial_branches, axis=1)

        if fuzzer_name in fuzzer_colors.keys():
            fuzzer_color = fuzzer_colors[fuzzer_name]
        else:
            fuzzer_color = random_rgb_color()

        median = list(np.insert(median,0,0))
        upper = list(np.insert(upper,0,0))
        lower = list(np.insert(lower,0,0))
        max_time = len(upper)

        fuzzer_to_cov.update({fuzzer_name:{"color": fuzzer_color, "median":median,"upper": upper, "lower":lower, "max_time": max_time, "crashes":ts_relative_crash_list,}})
    return fuzzer_to_cov
        

    #     if show_bands and plot_bands:
    #         ax.fill_between(np.arange(len(median[:max_time])), lower[:max_time], upper[:max_time], color=fuzzer_color, alpha = 0.15) # type: ignore
    #     ax.plot(np.arange(max_time), median[:max_time], color=fuzzer_color, alpha = 0.65, label=f"Median-{fuzzer_name}")
        
    #     times = list(np.arange(max_time))
        
    #     for crash_time in ts_relative_crash_list:
    #         if int(crash_time) in times:
    #             index = times.index(crash_time)

    #             plt.annotate('$\U00002629$', (crash_time, median[index]), color=fuzzer_color, textcoords="offset points", xytext=(0, -2), ha='center')
    #             # $\U0001F601$
    #     done = True

    # if done:
    #     # Add a legend for each unique color
    #     handles, labels = plt.gca().get_legend_handles_labels()
    #     by_label = dict(zip(labels, handles))
    #     plt.legend(by_label.values(), by_label.keys(), loc="lower right",  prop={'size': 4})

    #     plt.xlabel("Time (s)")
    #     plt.ylabel("Number of branches covered")
    #     ax.set_ylim(ymin=0)
    #     plt.savefig(f"plots/all_median.png",dpi=150)
    #     #plt.savefig(f"plots/all_median.svg",format="svg")
    #     plt.savefig(f"plots/incremental/median_{img_cnt:04d}.png",dpi=150)

    #     return True
    # else:
    #     print("Plotting failed")
    #     return False

def plotting(fuzzer_names : set[str] = set(), img_cnt = 0, fuzzer_colors : dict = {}, base_dir = Path("coverage_analysis"), plot_crashes : bool = False, save_svg = False) -> None:

    rcParams.update({'figure.autolayout': True})

    if not Path("plots").exists():
        Path("plots").mkdir()
        
    if save_svg:
        plot_suffix = "svg"
    else:
        plot_suffix = "png"
            
    
    if not Path("plots/incremental").exists():
        Path("plots/incremental").mkdir()
    fuzzer_to_cov: Dict[str, Dict] = calc_plot_data(fuzzer_names, img_cnt, fuzzer_colors, base_dir, plot_crashes) # type: ignore
    fig1, ax1 = plt.subplots()
    ax1 = plot_cov_line(ax1, fuzzer_to_cov)
    ax1.set_xlabel("Time (s)", fontsize=8)
    ax1.set_ylabel("Number of branches covered",fontsize=8)
    ax1.set_ylim(ymin=0)

    # Add a legend for each unique color
    handles, labels = plt.gca().get_legend_handles_labels()
    by_label = dict(zip(labels, handles))
    ax1.legend(by_label.values(), by_label.keys(), loc="lower right",  prop={'size': 6})
    fig1.tight_layout() 
    plt.autoscale()
    plt.savefig(f"plots/line_median.{plot_suffix}", format=plot_suffix, dpi=150, bbox_inches="tight")
    plt.close()

    fig2, ax2 = plt.subplots()
    ax2 = plot_cov_bar(ax2, fuzzer_to_cov)
    ax2.set_xlabel("Fuzzer Name", fontsize=8)
    ax2.set_ylabel("Number of branches covered", fontsize=8)
    ax2.set_ylim(ymin=0)
    fig2.tight_layout() 
    plt.autoscale()
    plt.xticks(fontsize=8, rotation=75)
    plt.savefig(f"plots/bar_median.{plot_suffix}", format=plot_suffix, dpi=150, bbox_inches="tight")

    # plt.savefig(f"plots/all_median.svg",format="svg")
    # plt.savefig(f"plots/incremental/median_{img_cnt:04d}.png",dpi=150)

def plot_cov_line(ax, fuzzer_to_cov : Dict[str, Dict]): # type: ignore

    # fuzzer_to_cov : {fuzzer_name:{"color": fuzzer_color, "median":median,"upper": upper, "lower":lower, "max_time": max_time, "crashes":ts_relative_crash_list,}}

    # fill each fuzzer line to the maximum
    max_time_to_fill = max([len(fuzzer_to_cov[fuzzer]["median"]) for fuzzer in fuzzer_to_cov])

    for fuzzer_name in fuzzer_to_cov:
        fuzzer_data = fuzzer_to_cov[fuzzer_name]
        fuzzer_color = fuzzer_data["color"]
        median: list[int] = fuzzer_data["median"]
        upper : list[int] = fuzzer_data["upper"]
        lower : list[int] = fuzzer_data["lower"]
        #max_time : int = fuzzer_data["max_time"]
        ts_relative_crash_list : list = fuzzer_data["crashes"]

        last_med = median[-1]
        last_upper = upper[-1]
        last_lower = lower[-1]

        while len(median) != max_time_to_fill:
            median.append(last_med)
            upper.append(last_upper)
            lower.append(last_lower)

        if show_bands and (len(lower) > 0 and  len(upper) > 0):
            ax.fill_between(np.arange(len(median[:max_time_to_fill])), lower[:max_time_to_fill], upper[:max_time_to_fill], color=fuzzer_color, alpha = 0.15) # type: ignore
        ax.plot(np.arange(max_time_to_fill), median[:max_time_to_fill], color=fuzzer_color, alpha = 0.65, label=f"Median-{fuzzer_name}")
        
        times = list(np.arange(max_time_to_fill))
        
        for crash_time in ts_relative_crash_list:
            if int(crash_time) in times:
                index = times.index(crash_time)

                plt.annotate('$\U00002629$', (crash_time, median[index]), color=fuzzer_color, textcoords="offset points", xytext=(0, -2), ha='center')

    return ax


def plot_cov_bar(ax, fuzzer_to_cov : Dict[str, Dict]): # type: ignore
    
    for fuzzer_name in fuzzer_to_cov:
        fuzzer_data = fuzzer_to_cov[fuzzer_name]
        fuzzer_color = fuzzer_data["color"]
        median: list[int] = fuzzer_data["median"]
        upper : list[int] = fuzzer_data["upper"]
        lower : list[int] = fuzzer_data["lower"]
        ax.bar(fuzzer_name, median[-1], color=fuzzer_color)
        ax.bar(fuzzer_name, upper[-1], color=fuzzer_color, alpha = 0.25)
        ax.bar(fuzzer_name, lower[-1], color="w", alpha = 0.25)
        
        print(f"lower: {lower[-1]}\tmedian: {median[-1]}\tupper: {upper[-1]}")
        
        ax.errorbar(fuzzer_name, median[-1], yerr = [[median[-1] - lower[-1]], [upper[-1] - median[-1]]], color="black")
    return ax

def gif_up():
    print("Generating gif!")
    if Path("plots/incremental/").exists():
        subprocess.call(["convert", "-delay", "10", "-loop", "0", "plots/incremental/*.png", "plots/fuzzer.gif"])
        print("Done --- fuzzer.gif")
    else:
        print("no path plots/incremental does not exist")

def interval_plot_thread(stop_event, interval : int = 0, fuzzer_names : set[str] = set(), plot_crashes : bool = False):

    cnt = 0
    fuzzer_colors = {}
    fuzzer_color = random_rgb_color()
    used_colors = set()

    try:
        if len(fuzzer_names) > 0:
            for fuzzer_name in fuzzer_names:
                if len(fuzzer_names) < 10:
                    fuzzer_color = random.choice(list(mcolors.TABLEAU_COLORS.keys()))
                    while fuzzer_color in list(fuzzer_colors.values()):
                        fuzzer_color = random.choice(list(mcolors.TABLEAU_COLORS.keys()))
                    fuzzer_colors.update({fuzzer_name:fuzzer_color})
                else:
                    for _ in range(len(fuzzer_names)): 
                        fuzzer_color = random_rgb_color()    
                        # Check if the color is sufficiently different from used colors
                        while not is_color_different(fuzzer_color, used_colors, threshold=0.75):
                            fuzzer_color = random_rgb_color()
                    fuzzer_colors.update({fuzzer_name:fuzzer_color})
    except Exception:
            tb = traceback.format_exc()
            print("Something went wrong!")
            with open("error.txt", "a") as fd:
                fd.write(str(tb))
            exit()

    while not stop_event.is_set():
        try:
            print("plotting...")
            calc_plot_data(fuzzer_names,cnt, fuzzer_colors=fuzzer_colors, plot_crashes=plot_crashes)
        except Exception as e:
            tb = traceback.format_exc()
            print("Something went wrong!")
            with open("error.txt", "a") as fd:
                fd.write(str(tb))
            exit()
        cnt += 1
        time.sleep(interval)

def process_crashes(base_dir : Path) -> None:
    print("  Processing crashes...")
    crash_res_file = Path(base_dir / "results/timestamp_to_crash.txt")
    ts_to_crash : list[tuple]  = get_crashes(base_dir)
    
    print("Processing crash")

    result_dir : Path = base_dir / "results"
    result_dir.mkdir(exist_ok=True)
    if not crash_res_file.exists():     
        print("Saving crashes")
        with open(crash_res_file,"w") as fd:
            for ts, crash in ts_to_crash:
                fd.write(f"{ts},{crash}\n")
    else:
        print("crash results already exists!")


def process_trial(trial : int, working_args, base_dir : Path):
    print(f"Processing trial: {trial} on base dir:{base_dir}")
    
    process_crashes(base_dir)

    return llvm_cov(working_args, str(trial), base_dir)

def log(log_value : str, log_file = "iterator_trial.txt"):
    print(log_value)
    with open(log_file, "a") as fd:
            fd.write(f"{log_value}\n")

def run_calc(num_threads : int, working_args, all_jobs, chunk_size : int = 20):

    with concurrent.futures.ProcessPoolExecutor(max_workers=chunk_size) as executor:
        # Submit the first chunk of trials asynchronously
        futures_list = [executor.submit(process_trial, trial, working_args, base_dir) for base_dir, trial in all_jobs]
        concurrent.futures.wait(futures_list, return_when=concurrent.futures.FIRST_EXCEPTION)
        


def run_calc_single(num_threads, working_args, all_jobs, chunk_size = 20):
   futures = {}
   with concurrent.futures.ProcessPoolExecutor(max_workers=num_threads-1) as executor:
        futures = {executor.submit(process_trial, trial, working_args, base_dir) for base_dir, trial in all_jobs}
        concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_EXCEPTION)


def run_calc_and_periodic_plot(executor, main_function, periodic_function, fuzzer_names : set[str], main_args, interval_seconds=60):
    stop_event = threading.Event()

    # Start the periodic function in a separate thread
    periodic_thread = threading.Thread(target=periodic_function, args=(stop_event, interval_seconds, fuzzer_names))
    periodic_thread.start()

    try:
        # Run the main function using the ProcessPoolExecutor
        with concurrent.futures.ThreadPoolExecutor() as thread_executor:
            future = thread_executor.submit(main_function, *main_args)
            concurrent.futures.wait(future, return_when=concurrent.futures.FIRST_EXCEPTION)


            # Wait for the main function to complete
            future.result()
    except KeyboardInterrupt:
        print("Execution interrupted. Cancelling ongoing tasks.")
        # Cancel the main function if interrupted
        future.cancel() # type: ignore
    finally:
        print("Finally called!")
        # Signal the stop event to terminate the periodic function
        stop_event.set()
        # Wait for the periodic function thread to complete
        periodic_thread.join()
        
        # create a gif from incremental files
        gif_up()

def parse_arguments(raw_args: Optional[Sequence[str]]) -> Namespace:
    parser: ArgumentParser = ArgumentParser(description="Controller for AFL++ restarting instances")
    
    parser.add_argument("--corpus", type=Path, default=None, help="Path to corpus base")
    parser.add_argument("--trials", type=int, default=10, help="Number of trials")
    parser.add_argument("--target", type=str, default="objdump", help="Target name")
    parser.add_argument("--cov_bin", type=Path, default=None, help="Path to llvm compiled coverage binary")
    parser.add_argument("--mode", type=str, default="afl", help="Set mode sileo | afl")
    parser.add_argument("--fuzzer_names", type=str, default="", help="Fuzzer names in quotes")
    parser.add_argument("--target_args", type=str, default="", help="Target arguments, use quotes")
    parser.add_argument("--calc", action="store_true", default=False, help="Calculate coverage")
    parser.add_argument("--res", action="store_true", default=False, help="Print results of mode")
    parser.add_argument("--plot", action="store_true", default=False, help="Plot results of mode")
    parser.add_argument("--gif", action="store_true", default=False, help="Create a gif from plot/incremental/*.png")
    parser.add_argument("--skip", action="store_true", default=False, help="Skip corpus copy. WARNING: rsync will anyways check for files left")
    parser.add_argument("--testing", action="store_true", default=False, help="Testing Mode (no multiprocessing)")
    parser.add_argument("--show_bands", action="store_true", default=False, help="Show percentile bands")
    parser.add_argument("--regex", type=str, default="", help="Regex to get specific filename identifier: e.g.\n\t\tdirectory: afl_0 afl_1 ...\n\t\tregex: afl_[0-9]*")
    parser.add_argument("--strip", type=str, default="", help="Strip the resulting fuzzer names by given character")
    parser.add_argument("--threads", type=int, default=80, help="Maximum number of threads")
    parser.add_argument("--parallel_trials", type=int, default=20, help="Maximum number of parallel trials / runs to calculate (to reduce disk usage)")
    parser.add_argument("--crashes", action="store_true", default=False, help="Get crashes")
    parser.add_argument("--regcheck", action="store_true", default=False, help="List found fuzzers by your given regex")
    parser.add_argument("--svg", action="store_true", default=False, help="Save plots as SVG")
    
    
    return parser.parse_args(raw_args)


def main(raw_args: Optional[Sequence[str]] = None):
    global skip_corpus, mode, show_bands, regex
    
    args: Namespace = parse_arguments(raw_args)

    working_args: dict = gen_arguments(args)
    mode = working_args["mode"]
    skip_corpus = args.skip
    fuzzer_info = []
    show_bands = args.show_bands

    regex = args.regex

    if skip_corpus:
        print("Skipping corpus copy!!\nI hope you know what you are doing and you have the correct corpus here... 5sec to think about")
        time.sleep(5)

    if args.regcheck:
        fuzzer_names = get_all_fuzzer(working_args, cstrip=args.strip)
        print("found the following fuzzers")
        print(fuzzer_names)
        exit()


    if args.calc:

        fuzzer_names = get_all_fuzzer(working_args, cstrip=args.strip)
        print("found the following fuzzers")
        print(fuzzer_names)

        num_trials = working_args["trials"]
        all_jobs = []

        for i, fuzzer_name in enumerate(fuzzer_names):
            print(f"Fuzzer: {fuzzer_name}")
            base_dir = Path("coverage_analysis") / fuzzer_name
            mount_corpus(working_args, base_dir, fuzzer_name, umount=True)
            create_directory_structure(base_dir, skip_corpus)
            
            mount_corpus(working_args, base_dir, fuzzer_name)
            #copy_corpus(working_args, base_dir, fuzzer_name)
            fuzzer_info.append(base_dir)
            all_jobs.extend(list(zip([base_dir] * num_trials, range(num_trials))))
            print(f"Done: {i+1}/{len(fuzzer_names)}\n")

        print(f"All jobs: {len(all_jobs)}")
        # testing
        if args.testing:
            for base_dir, trial in all_jobs:
                process_trial(trial, working_args, base_dir)
        else:    
            main_args = (args.threads, working_args, all_jobs, args.parallel_trials)
            run_calc_and_periodic_plot(concurrent.futures.ProcessPoolExecutor(), run_calc, interval_plot_thread, fuzzer_names, main_args, interval_seconds=30)
                
        print("All trials processed.")

    
    if args.res:
        print("not implemented")

    if args.plot:
        if args.fuzzer_names != "":
            fuzzer_names = args.fuzzer_names.split(",")
        else:
            fuzzer_names = get_all_fuzzer(working_args, cstrip=args.strip)

        print(fuzzer_names)
        
        plotting(set(fuzzer_names), plot_crashes=args.crashes, save_svg = args.svg)
        #+calc_plot_data(set(fuzzer_names), plot_crashes=args.crashes)

    if args.gif:
        gif_up()


if __name__ == "__main__":
    main()
