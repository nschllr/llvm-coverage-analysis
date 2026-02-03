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
import sys
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
from threading import Lock
from typing import Any, Dict, List, Optional, Sequence
import re
import time
import shlex
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
from matplotlib import rcParams
import numpy as np
import subprocess
import hashlib
from natsort import natsorted
import random

from matplotlib import rc

# rc('font', **{'family': 'serif', 'serif': ['Computer Modern']})
# rc('text', usetex=True)

CONTAINER_NAME = "llvm_cov_analysis"
skip_corpus = False
show_bands = False
regex = ""
num_trials = 0
llvm_version = None
all_jobs_len = 0
accuracy = 0.0
jobs_done = [0]
other_testcase_dir = None


def get_creation_time(item):
    return item.stat().st_ctime

def get_testcases(corpus_path: Path, fuzzer_type : str = "afl", other_base_dir: Optional[Path] = None, include_other: bool = True) -> list[Path]:
    print(f"Gathering testcases from {corpus_path.as_posix()}")
    # filter out .state directories (redundant_edges ...)
    
    if fuzzer_type == "afl":
        testcases = sorted(tc for tc in corpus_path.glob("id:*") if not ".state" in tc.as_posix())
    else:

        testcases_unsrt_all = corpus_path.iterdir()
        testcases_unsrt = [testcase for testcase in testcases_unsrt_all if not "." in testcase.name]
        testcases = sorted(testcases_unsrt, key=get_creation_time)
            
    if include_other and other_testcase_dir is not None:
        other_dir = Path(other_testcase_dir)
        if str(other_dir) != "":
            if not other_dir.is_absolute():
                base_dir = other_base_dir if other_base_dir is not None else corpus_path
                other_dir = base_dir / other_dir
            if other_dir.exists():
                print(f"Found other testcases directory: {other_dir}")
                other_testcases = sorted(tc for tc in other_dir.glob("**/id:*") if ".state" not in tc.as_posix())
                print(f"Adding {len(other_testcases)} testcases from other directory")
                testcases.extend(other_testcases)
                if fuzzer_type == "afl":
                    testcases = sorted(testcases)
                else:
                    testcases = sorted(testcases, key=get_creation_time)
            else:
                print(f"Other testcases directory not found: skipping {other_dir}")
        
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
    trial_idf = working_args["trial_idf"]
    corpus_base_path = working_args["corpus_path"]
    if trial_idf != "":
        print(f"Searching for trial: {trial_idf} in {corpus_base_path}")
        trial_paths : list[Path] = list(corpus_base_path.glob(f"{fuzzer_name}/{trial_idf}"))
    else:
        trial_paths : list[Path] = list(corpus_base_path.glob(f"*{fuzzer_name}*"))
    
    print("trial_paths:",trial_paths)
    
    if len(trial_paths) == 0:
        # fuzzbench trials
        print("Found fuzzbench trials")
        trial_paths : list[Path] = list(corpus_base_path.glob(f"trial*"))

    for trial_id, trial_path in enumerate(trial_paths):

        use_sudo = os.geteuid() != 0
        
        dest_path = Path(base_dir / "tmp" / "full_corpus" / f"trial_{trial_id}")
        if not umount:
            print(f"creating trial: trial_{trial_id}")
            (base_dir / "tmp" / "full_corpus" / f"trial_{trial_id}").mkdir(exist_ok=True)
            (base_dir / "profraw_files" / f"trial_{trial_id}").mkdir(exist_ok=True, parents=True)
            (base_dir / "profdata_files" / f"trial_{trial_id}").mkdir(exist_ok=True, parents=True)
            cmd = ["mount", "-r", "-B", "-v", trial_path.as_posix() + "/", dest_path]
            if use_sudo:
                cmd.insert(0, "sudo")
            res = subprocess.run(cmd)
            if res.returncode != 0:
                print("Error: mount failed. Ensure the container is privileged or has CAP_SYS_ADMIN.")
                sys.exit(1)
        else:
            cmd = ["umount", "-v", dest_path]
            if use_sudo:
                cmd.insert(0, "sudo")
            res = subprocess.run(cmd)

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
        #print(f"Grouping file {file} under minute {minute}")
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

def find_fuzzer_stats_for_queue(q: Path) -> Path:
    # Usually: .../default/queue  -> .../default/fuzzer_stats
    cand = q.parent / "fuzzer_stats"
    if cand.exists():
        return cand
    # Fallback: nearest fuzzer_stats upward in this run tree
    for parent in q.parents:
        fs = parent / "fuzzer_stats"
        if fs.exists():
            return fs
    raise FileNotFoundError(f"No fuzzer_stats found for queue dir: {q}")

def gen_profraw_data(testcases_to_starttime: list[tuple], start, target_bin: Path, target_args: str, profraw_dir: Path, trial, base_dir: Path, legacy_or_libafl: bool):
    print(f"Generating profraw data from testcases... ({trial} - {base_dir.name})")
    cov_times = []
    tts_len = len(testcases_to_starttime)

    for i, testcase_to_starttime in enumerate(testcases_to_starttime, start=start):
        afl_version, starttime, testcase = testcase_to_starttime
        
        progress_mod = max(1, int(tts_len * 0.2))
        merge_mod = max(1, int(tts_len * 0.3))
        if i % progress_mod == 0:
            print(f"[{jobs_done[0]}/{all_jobs_len}] Processing Testcase {trial} - {base_dir.name}:\t {i}/{start+len(testcases_to_starttime)} -- {round(i / (start+len(testcases_to_starttime))*100,2)}%")
            
        if (i % merge_mod == 0 and i > 0) or i == len(testcases_to_starttime) - 1:
            profraw_files : list[Path] = sorted(list(profraw_dir.iterdir()))
            file_groups = group_files_by_minute(profraw_files)

            print("Start multiprocessed merging by minute")
            with concurrent.futures.ProcessPoolExecutor() as executor:
                futures = []
                for minute, files in file_groups.items():
                    #merge_by_minute_single(files, minute, trial)
                    futures.append(executor.submit(merge_by_minute_single, files, minute, trial))
                concurrent.futures.wait(futures)

        cov_time: int = 0

        if legacy_or_libafl:
            testcase_time = get_creation_time(testcase)
            cov_time = testcase_time
        else:
            # some afl++ version did not assign a time to "orig:" testcases
            if ",time:" not in testcase.name:
                testcase_time = 0
            else:
                testcase_time = testcase.name.split(",time:")[1].split(",")[0]
                # some afl++ versions have a "+" in the timestamp for splicing
                if "+" in testcase_time:
                    testcase_time = testcase_time.split("+")[0] 
            cov_time = int(starttime) + int(testcase_time) // 1000
            #print(f"testcase: {testcase} \t testcase_time: {testcase_time} \t starttime: {starttime} \t cov_time: {cov_time}")
        cov_times.append(cov_time)
        profraw_file = f"{profraw_dir}/llvm_{i:08d}_ts:{cov_time}.profraw"
        assert Path(profraw_file).exists() == False, f"profraw file already exists: {profraw_file}"
        
        os.environ["LLVM_PROFILE_FILE"] = profraw_file

        args_list = shlex.split(target_args)
        target_args_w_input = [arg.replace("@@", str(testcase)) for arg in args_list]
        llvm_target_cmd = [str(target_bin), *target_args_w_input]
        execute_cmd(llvm_target_cmd)
    print(f"\nGenerating profraw files done ({trial} - {base_dir.name})!")
    
    
def preprocess_afl(queue_dir : Path, testcases_to_starttime : list[tuple], trial_root: Optional[Path]) -> tuple[list[tuple], bool]:
    print(f"Preprocessing afl testcases in {queue_dir}")
    fuzzer_stats = find_fuzzer_stats_for_queue(queue_dir)
    testcases: list[Path] = get_testcases(queue_dir, other_base_dir=trial_root)
    starttime: str = get_starttime(fuzzer_stats)
    afl_version: str = get_afl_version(fuzzer_stats)
    legacy_afl = check_legacy_afl(afl_version)

    testcases_to_starttime.extend(list(zip([afl_version] * len(testcases), [starttime] * len(testcases), testcases)))
    return testcases_to_starttime, legacy_afl

def preprocess_libafl(queue_dir : Path, testcases_to_starttime : list[tuple], trial_root: Optional[Path]) -> list[tuple]:
    print(f"Preprocessing libafl testcases in {queue_dir}")
    testcases: list[Path] = get_testcases(queue_dir, fuzzer_type = "libafl", other_base_dir=trial_root)
    if len(testcases) == 0:
        print(f"No testcases found in {queue_dir}")
        return testcases_to_starttime
    # for libafl we don't have a starttime yet, so we set it to 0
    starttime: str = int(get_creation_time(testcases[0])).__str__()
    afl_version: str = "libafl"
    testcases_to_starttime.extend(list(zip([afl_version] * len(testcases), [starttime] * len(testcases), testcases)))
    return testcases_to_starttime    


def llvm_cov(working_args, trial: str, base_dir: Path) -> tuple[bool, Path]:
    
    trial = f"trial_{trial}"
    full_corpus : Path = base_dir / "tmp" / "full_corpus"
    profraw_dir : Path = base_dir / "profraw_files" / trial
    profdata_dir : Path = base_dir / "profdata_files" / trial
    target_bin = working_args["cov_bin"]
    target_args = working_args["target_args"]
    fuzzer_type = working_args["fuzzer_type"]
    clean_up(profdata_dir, create = True)

    print("Starting llvm coverage analysis")

    starttime = ""
    testcases = []
    
    print("full_corpus:",full_corpus / trial)

    queue_dirs : list[Path] = natsorted(list(Path(full_corpus / trial).glob("**/queue")))
    # fuzzer_stats_paths : list[Path] = natsorted(list(Path(full_corpus / trial).glob("**/fuzzer_stats")))

    # # there should be the same amount of fuzzer_stats files as queue_dirs otherwise, something is wrong
    # assert len(queue_dirs) > 0, f"Found no queue dirs: {len(queue_dirs)} -- {queue_dirs} "
    # assert len(fuzzer_stats_paths) > 0, f"Found no queue dirs: {len(fuzzer_stats_paths)} -- {fuzzer_stats_paths} "

    # if len(queue_dirs) != len(fuzzer_stats_paths):
    #     print(f"Found a different amount of fuzzer_stats files and queue directorys: Queues: {len(queue_dirs)} -- stats: {len(fuzzer_stats_paths)}")
    #     assert len(queue_dirs) == len(fuzzer_stats_paths), "different len of queue and fuzzer_stats"
    fuzzer_stats_paths = []
    if fuzzer_type == "afl":
        fuzzer_stats_paths : list[Path] = natsorted(list(Path(full_corpus / trial).glob("**/fuzzer_stats")))
        assert len(fuzzer_stats_paths) > 0, f"Found no queue dirs: {len(fuzzer_stats_paths)} -- {fuzzer_stats_paths} "
        assert len(queue_dirs) > 0, f"Found no queue dirs: {len(queue_dirs)} -- {queue_dirs} "
            
        if len(queue_dirs) != len(fuzzer_stats_paths):
            print(f"Found a different amount of fuzzer_stats files and queue directorys: Queues: {len(queue_dirs)} -- stats: {len(fuzzer_stats_paths)}")
            assert len(queue_dirs) == len(fuzzer_stats_paths), "different len of queue and fuzzer_stats"
        
        # asume that all queues of the fuzzer have the same afl version -- so the first one will do it

    elif fuzzer_type == "libafl":
        assert len(queue_dirs) > 0, f"Found no queue dirs: {len(queue_dirs)} -- {queue_dirs} "
    
    else:
        print(f"Error: unknown fuzzer type: {fuzzer_type}")
        exit(1)
    
    

    legacy_afl : bool | None = None

    clean_up(profdata_dir, create = True)
    start = 0
    for queue_dir in queue_dirs:
        testcases_to_starttime: list[tuple] = [] 
        # fuzzer_stats = find_fuzzer_stats_for_queue(queue_dir)
        # print(queue_dir)
        # print(fuzzer_stats, "\n")

        # testcases = get_testcases(queue_dir)
        # starttime  = get_starttime(fuzzer_stats)
        # afl_version = get_afl_version(fuzzer_stats)
        # if legacy_afl is None:
        #     legacy_afl = check_legacy_afl(afl_version)
            
        # print(f"queue_dir: {queue_dir}\nfuzzer_stats: {fuzzer_stats}\t starttime: {starttime}")

        # testcases_to_starttime.extend((afl_version, starttime, tc) for tc in testcases)
        legacy_afl = False
        if fuzzer_type == "afl":
            testcases_to_starttime, legacy_afl = preprocess_afl(queue_dir, testcases_to_starttime, full_corpus / trial)    
        elif fuzzer_type == "libafl":
            testcases_to_starttime = preprocess_libafl(queue_dir, testcases_to_starttime, full_corpus / trial)
            legacy_afl = True
        else:
            print(f"Error: unknown fuzzer type: {fuzzer_type}")
            exit(1)
        
        gen_profraw_data(testcases_to_starttime, start, target_bin, target_args, profraw_dir, trial, base_dir, legacy_afl)
        start += len(testcases_to_starttime)
    

    # profraw_files : list[Path] = sorted(list(profraw_dir.iterdir()))
    # file_groups = group_files_by_minute(profraw_files)

    # print("Start multiprocessed merging by minute")
    # with concurrent.futures.ProcessPoolExecutor() as executor:
    #     futures = []
    #     for minute, files in file_groups.items():
    #         # merge_by_minute_single(files, minute, trial)
    #         futures.append(executor.submit(merge_by_minute_single, files, minute, trial))
    #     concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_EXCEPTION)
        

    print(f"[{jobs_done[0]}/{all_jobs_len}] Merging and exporting data profdata... ({trial} - {base_dir.name})")

    profdata_files : list[Path] = sorted(list(profdata_dir.iterdir()))
    timestamp_to_b_covered : list[tuple]= []
    profdata_file_final: Path = profdata_dir / f"llvm-final.profdata"

    for id, profdata_file in enumerate(profdata_files):
        if not profdata_file.name.endswith("profdata"):
            continue

        timestamp = extract_timestamp(profdata_file)
        if profdata_file_final.exists():
            llvm_profdata_cmd: str = f"llvm-profdata-{llvm_version} merge -sparse {profdata_file} {profdata_file_final} -o {profdata_file_final}"
        else:
            llvm_profdata_cmd: str = f"llvm-profdata-{llvm_version} merge -sparse {profdata_file} -o {profdata_file_final}"

        #print(f"Running command ({trial} - {base_dir.name}): {llvm_profdata_cmd}")
        print(f"[{jobs_done[0]}/{all_jobs_len}] Processing (merge profdata) ({trial} - {base_dir.name} -- timestamp: {datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M')}): {id}/{len(profdata_files)} -- {round(id / len(profdata_files)*100,2)}%")
        
        execute_cmd(llvm_profdata_cmd.split(" "), check = True)
        accuracy_corrected = round(1.0 - accuracy,2)
        boundary = int(len(profdata_files) * accuracy_corrected)
        if boundary < 1:
            boundary = 1
        
        # export the first 10 profdata files if the accuracy is greater than 0.5 and after that use the boundary
        # this is due to the fact the in first few minutes / hours more coverage is found than later
        profdata_5_perc = int(len(profdata_files) * 0.05)
        # if id % boundary == 0 and id > 0 or id == len(profdata_files) - 1:
        if (id == 0) or (id in range(0,profdata_5_perc) and accuracy > 0.5) or ((id % boundary == 0 and id > 0) or id == len(profdata_files) - 1): 
            llvm_export_cmd = f"llvm-cov-{llvm_version} export -format=text -region-coverage-gt=0 {target_bin} -skip-expansions -instr-profile={profdata_file_final}"
            print(f"[{jobs_done[0]}/{all_jobs_len}] Running export command ({trial} - {base_dir.name})")
            res = execute_cmd(llvm_export_cmd.split(" "), capture_output=True)
            report_data = json.loads(res.stdout)
            
            # branch_count = calculate_cov_branches(report_data["data"][0]["files"])
            # branch_count = get_branches_covered(report_data)
            branch_count = report_data["data"][0]["totals"]["branches"]["covered"]
            
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
                
            with open(f"{profdata_dir}/export_info.txt", "w") as fd:
                fd.write(f"ID: {id}/{len(profdata_files)}\t timestamp: {timestamp} \tbranch count: {branch_count}\n")

        profdata_file.unlink()
    #jobs_done += 1
    #with lock:
    #    jobs_done[0] += 1
    print(f"[{jobs_done[0]}/{all_jobs_len}] Export done ({trial} - {base_dir.name})")

    # cleanup to save space
    clean_up(profraw_dir)
    #clean_up(full_corpus)

    return True, base_dir

def merge_by_minute_single(files : list[Path], minute, trial):
    timestamp = int(datetime.strptime(minute, '%Y-%m-%d %H:%M').timestamp())
    print(f"Merging data for timestamp ({trial}): {minute} --- \t{len(files)} files")

    profdata_dir = files[0].parent.parent.parent / "profdata_files" / trial
    # temporary save files
    fd, profdata_save_file = tempfile.mkstemp(dir=profdata_dir, prefix="llvm_tmp_", suffix=".txt")
    os.close(fd)
    with open(profdata_save_file, "w") as fd_out:
        for profraw_file in files:
            fd_out.write(f"{profraw_file}\n")

    new_profdata_file: str = f"{profdata_dir}/llvm_ts:{timestamp}.profdata"
    llvm_profdata_cmd: str = f"llvm-profdata-{llvm_version} merge -sparse -f {profdata_save_file} -o {new_profdata_file}"
    execute_cmd(llvm_profdata_cmd.split(" "), check=True)

    # deleting old files
    for profraw_file in files:
        profraw_file.unlink()
    Path(profdata_save_file).unlink()

def clean_up(dir_path : Path, create : bool = False):
    print(f"Cleaning up: {dir_path}")
    if dir_path.exists():
        shutil.rmtree(dir_path)

    if create:
        dir_path.mkdir(parents=True)

def execute_cmd(cmd : List[str], capture_output=True, check = False):
    # print(f"command: " + " ".join(cmd))
    res = subprocess.run(list(filter(None, cmd)), capture_output=capture_output, check=check)

    return res


def get_branches_covered(json_data) -> int:
    return int(json_data["data"][0]["totals"]["branches"]["covered"])

def get_crashes(base_dir : Path, result_crash_dir : Path):
    print("     Get crashes...")
    full_corpus : Path = base_dir / "tmp" / "full_corpus"
    print(full_corpus)
    crash_dirs : list = list(full_corpus.glob("**/crashes/"))
    crashes : list[Path] = []

    result_crash_dir.mkdir(exist_ok=True, parents=True)
    
    print(f"Number of crash dirs: {len(crash_dirs)}")

    for crash_dir in crash_dirs:
        crashes.extend(get_testcases(crash_dir, include_other=False))
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
        crash_stats = list(crash.parent.parent.glob("./**/fuzzer_stats"))
        if not crash_stats:
            print(f"No fuzzer_stats found for crash: {crash}")
            continue
        crash_fs_path : Path = crash_stats[0]
        print(f"found fuzzer_stats for crash: {crash_fs_path}")
        starttime = get_starttime(crash_fs_path)
        if ",time:" not in crash.name:
            print(f"No crash timestamp found in name: {crash.name}")
            continue
        crash_timestamp = crash.name.split(",time:")[1].split(",")[0]
        ts_to_crash.append((int(starttime) + int(crash_timestamp) // 1000,crash))
        
        print(f"Copying crash: {crash}")
        shutil.copy(crash, result_crash_dir)

    return ts_to_crash


def get_hash(file: Path) -> str:
    with open(file, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()

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

    if args.corpus is None and args.calc:
        print("No corpus path given. Exiting")
        exit()
    else:
        corpus_path : Path = args.corpus
   
    if args.work_dir is None:
        base_dir : Path = Path("./")
    else:
        base_dir : Path = args.work_dir
    
    if args.cov_bin is None and args.calc:
        print("No coverage binary path given. Exiting")
        exit()
    else:
        if args.cov_bin.exists():
            cov_bin_path : Path = args.cov_bin
        else:
            print("Coverage binary does not exist!")
            exit()
            
    if args.crash_binary is not None and args.crash_binary.exists():
        crash_bin : Path = args.crash_binary
    else:
        crash_bin = None        
        
    trials : int = args.trials
    target_name : str = args.target

    return {"work_dir": base_dir, "corpus_path": corpus_path, "cov_bin": cov_bin_path, "trials" : trials, "trial_idf" : args.trial_idf, "target_name": target_name, "target_args": args.target_args, "crash_bin" : crash_bin, "fuzzer_type" : args.fuzzer_type}

def random_rgb_color():
    return tuple(np.random.rand(3,))

def color_difference(color1, color2):
    return sum((c1 - c2) ** 2 for c1, c2 in zip(color1, color2))

def is_color_different(color, used_colors, threshold=0.5):
    for used_color in used_colors:
        if color_difference(color, used_color) < threshold:
            return False
    return True


def calc_plot_data(fuzzer_names : set[str] = set(), fuzzer_colors : dict = {}, base_dir = Path("coverage_analysis")):# -> dict[str, Dict[Any, Any]]:

    if not Path("plots").exists():
        Path("plots").mkdir()    
    
    if not Path("plots/incremental").exists():
        Path("plots/incremental").mkdir()

    used_colors = set()

    if len(fuzzer_names) > 0 and len(fuzzer_colors) == 0:
        for fuzzer_name in sorted(fuzzer_names):
            if len(fuzzer_names) == 2:
                fuzzer_colors.update({fuzzer_name: "tab:blue" if len(fuzzer_colors) < 1 else "tab:orange"})
            elif len(fuzzer_names) > 2 and len(fuzzer_names) <= 10:
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
    #num_trials = len(all_ts_data_paths) // len(fuzzer_names)
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
        if ts_to_crash_file.exists():
            with open(ts_to_crash_file.as_posix(),"r") as fd:
                ts_to_crashes: list[str] = fd.readlines()

        ts_crash_list: list[int] = []

        for ts_to_crash in ts_to_crashes:
            ts =  ts_to_crash.split(",")[0] 
            #ts_to_crash_dict.update({ts : crash})
            ts_crash_list.append(int(ts))

        trial_results_branches: list[list] = []
        trial_results_ts: list[list] = []

        ts_relative_crash_list = []
        trial_to_branches = []
        
        for ts_to_branch_file in all_trial_paths:
            ts_to_branch = []
            with open(ts_to_branch_file.as_posix(),"r") as fd:
                ts_to_branch: list[str] = fd.readlines()
            ts_to_branch = sorted(ts_to_branch)
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
            #print(f"ts_to_branch_file: {ts_to_branch_file} --- last branch: {branches_covered_list[-1]}")
            trial_to_branches.append((ts_to_branch_file, branches_covered_list[-1])) # type: ignore
            trial_results_branches.append(branches_covered_list)
            trial_results_ts.append(ts_list)
        print(trial_to_branches)

        for e,i in enumerate(sorted(trial_to_branches, key=lambda x: x[1])):
            if e == len(trial_to_branches)//2:
                print(f"{i[0]} ----- covered branches: {i[1]} <--- MEDIAN")
                median_run = i
            else:
                print(f"{i[0]} ----- covered branches: {i[1]}")

        if len(trial_results_branches) == 0:
            continue
        all_trial_branches = []
        max_num_entries: int = max([len(x) for x in trial_results_branches])
        
        corrected_trial_results_branches = []
        for trial_branches in trial_results_branches:
        
            if len(trial_branches) < max_num_entries:
                trial_branches.extend([trial_branches[-1]] * (max_num_entries - len(trial_branches)))
            corrected_trial_results_branches.append(trial_branches)
                
        if max_num_entries < 2:
            continue
        for idx in range(max_num_entries):
            value_series = []
            for trial_idx in range(len(corrected_trial_results_branches)):
                value_series.append(corrected_trial_results_branches[trial_idx][idx])
                #print(f"{corrected_trial_results_branches[trial_idx][idx]=}")
            all_trial_branches.append(value_series)

        lower = []
        upper = []
        plot_bands = False
        try:
            # calculate lower and upper bound for percentile by number of trials
            l_perc = int(0.33 * num_trials)
            u_perc = int(0.66 * num_trials) + 1 
            
            #print(f"Calculating percentile: {l_perc} - {u_perc}")
            for values in all_trial_branches:
                d_interval = sorted(values)#[l_perc:u_perc]
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


def plotting(fuzzer_names : set[str] = set(), while_calc = False, img_cnt = 0, fuzzer_colors : dict = {}, base_dir = Path("coverage_analysis"), plot_crashes : bool = False, save_format = "png", plot_desciption = "", annotation_file = None) -> None:

    rcParams.update({'figure.autolayout': True})
    plot_dir = base_dir.parent / "plots"

    if not plot_dir.exists():
        plot_dir.mkdir()
        
    if save_format not in ["png", "svg", "pdf"] or while_calc:
        plot_suffix = "png"
    else:
        plot_suffix = save_format
              
    if not Path(plot_dir / "incremental").exists():
        Path(plot_dir / "incremental").mkdir()
    fuzzer_to_cov: Dict[str, Dict] = calc_plot_data(fuzzer_names, fuzzer_colors, base_dir) # type: ignore
    if len(fuzzer_to_cov) == 0:
        print("No coverage data found to plot.")
        return
    fig1, ax1 = plt.subplots(figsize=(6,5))
    ax1 = plot_cov_line(ax1, fuzzer_to_cov, plot_crashes, while_calc=while_calc,annotation_file=annotation_file)
    ax1.set_xlabel("Time (hours)", fontsize=10)
    ax1.set_ylabel("Branches Covered",fontsize=10)
    ax1.set_ylim(ymin=0)
    #ax1.set_yscale('log')

    # Add a legend for each unique color
    handles, labels = plt.gca().get_legend_handles_labels()
    by_label = dict(zip(labels, handles))
    ax1.legend(by_label.values(), by_label.keys(), loc="lower right",  prop={'size': 10},ncols=2)
    fig1.tight_layout() 
    plt.autoscale()
    plt.title(plot_desciption)
    plt.savefig(f"{plot_dir.as_posix()}/line_median.{plot_suffix}", format=plot_suffix, bbox_inches="tight")
    
    if while_calc:
        plt.savefig(f"{plot_dir.as_posix()}/incremental/line_median_{img_cnt:04d}.{plot_suffix}", format=plot_suffix, bbox_inches="tight")
    plt.close()

    if not while_calc:
        fig2, ax2 = plt.subplots()
        ax2 = plot_cov_bar(ax2, fuzzer_to_cov)
        ax2.set_xlabel("Fuzzer Name", fontsize=10)
        ax2.set_ylabel("Branches Covered", fontsize=10)
        ax2.set_ylim(ymin=0)
        fig2.tight_layout() 
        plt.autoscale()
        plt.xticks(fontsize=10, rotation=75)
        plt.title(plot_desciption, size = 10)
        plt.savefig(f"{plot_dir.as_posix()}/bar_median.{plot_suffix}", format=plot_suffix, bbox_inches="tight")
        
    print(plot_desciption)

from pathlib import Path
from typing import Dict
import numpy as np
import matplotlib.pyplot as plt

SEC_TO_HOURS = 1.0 / 3600.0

def plot_cov_line(ax, fuzzer_to_cov: Dict[str, Dict], plot_crashes, while_calc: bool = False, annotation_file = None):  # type: ignore
    # fuzzer_to_cov : {fuzzer_name:{
    #   "color": fuzzer_color, "median":median,"upper": upper, "lower":lower,
    #   "max_time": max_time, "crashes": ts_relative_crash_list,
    # }}

    # fill each fuzzer line to the maximum
    if while_calc:
        max_time_to_fill = 0
    else:
        max_time_to_fill = max(len(fuzzer_to_cov[f]["median"]) for f in fuzzer_to_cov)

    for fuzzer_name in fuzzer_to_cov:
        fuzzer_data = fuzzer_to_cov[fuzzer_name]
        fuzzer_color = fuzzer_data["color"]
        median: list[int] = fuzzer_data["median"]
        upper:  list[int] = fuzzer_data["upper"]
        lower:  list[int] = fuzzer_data["lower"]
        max_time: int  = fuzzer_data["max_time"]      # seconds
        ts_relative_crash_list: list = fuzzer_data["crashes"]  # seconds

        last_med   = median[-1]
        last_upper = upper[-1]
        last_lower = lower[-1]

        if while_calc:
            max_time_to_fill = max_time
        else:
            while len(median) != max_time_to_fill:
                median.append(last_med)
                upper.append(last_upper)
                lower.append(last_lower)

        # x in HOURS
        x_hours = np.arange(max_time_to_fill) * SEC_TO_HOURS
        n = len(median[:max_time_to_fill])  # safe length for plotting

        if show_bands and (len(lower) > 0 and len(upper) > 0):
            ax.fill_between(
                x_hours[:n],
                lower[:max_time_to_fill][:n],
                upper[:max_time_to_fill][:n],
                color=fuzzer_color,
                alpha=0.15  # type: ignore
            )

        ax.plot(
            x_hours[:n],
            median[:max_time_to_fill][:n],
            color=fuzzer_color,
            alpha=0.65,
            label=f"Median-{fuzzer_name}"
        )

        if plot_crashes:
            med_arr = median[:max_time_to_fill]
            for crash_time in ts_relative_crash_list:
                ct = int(crash_time)
                if 0 <= ct < len(med_arr):
                    ax.annotate(
                        '$\U00002629$',
                        (ct * SEC_TO_HOURS, med_arr[ct]),
                        color=fuzzer_color,
                        textcoords="offset points",
                        xytext=(0, -2),
                        ha='center'
                    )

    # Vertical annotations (timestamps in seconds) -> convert to hours
    if annotation_file != None:
        ann = []
        with open(annotation_file, "r") as fd:
            for line in fd:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                try:
                    ann.append(int(float(s)))
                except ValueError:
                    continue

        first_label_drawn = False
        for t in ann:
            if 0 <= t < max_time_to_fill:
                ax.axvline(
                    x=t * SEC_TO_HOURS,
                    linestyle='--',
                    linewidth=0.6,
                    color='k',
                    alpha=0.65,
                    zorder=0,
                    label=("Restart" if not first_label_drawn else None)
                )
                first_label_drawn = True

    ax.set_xlabel("Time (hours)")
    import matplotlib.ticker as ticker
    ax.xaxis.set_major_locator(ticker.MultipleLocator(4))
    return ax



def plot_cov_bar(ax, fuzzer_to_cov : Dict[str, Dict]): # type: ignore
    
    for fuzzer_name in fuzzer_to_cov:
        fuzzer_data = fuzzer_to_cov[fuzzer_name]
        fuzzer_color = fuzzer_data["color"]
        median: list[int] = fuzzer_data["median"]
        upper : list[int] = fuzzer_data["upper"]
        lower : list[int] = fuzzer_data["lower"]
        print(f"{fuzzer_name} -\tlower: {lower[-1]}\tmedian: {median[-1]}\tupper: {upper[-1]}")
        ax.bar(fuzzer_name, median[-1], color=fuzzer_color)
        ax.bar(fuzzer_name, upper[-1], color=fuzzer_color, alpha = 0.25)
        ax.bar(fuzzer_name, lower[-1], color="w", alpha = 0.25)       
        ax.errorbar(fuzzer_name, median[-1], yerr = [[median[-1] - lower[-1]], [upper[-1] - median[-1]]], color="black")
    return ax

def gif_up():
    print("Generating gif!")
    if Path("plots/incremental/").exists():
        subprocess.call(["convert", "-delay", "10", "-loop", "0", "plots/incremental/*.png", "plots/fuzzer.gif"])
        print("Done --- fuzzer.gif")
    else:
        print("no path plots/incremental does not exist")

def interval_plot_thread(stop_event, interval : int = 0, fuzzer_names : set[str] = set(), plot_crashes : bool = False, base_dir = Path("coverage_analysis")) -> None:

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
            plotting(fuzzer_names, while_calc = True, img_cnt = cnt, fuzzer_colors=fuzzer_colors, base_dir=base_dir, plot_crashes=plot_crashes)
        except Exception as e:
            tb = traceback.format_exc()
            print("Something went wrong!")
            with open("error.txt", "a") as fd:
                fd.write(str(tb))
            exit()
        cnt += 1
        time.sleep(interval)
    print("Plotting Stopped!")

def process_crashes(base_dir : Path, working_args : Dict[str, Any]) -> None:
    
    crashing_binary : Path = working_args["crash_bin"]
    target_args : str = working_args["target_args"]
    
    if crashing_binary == None or not crashing_binary.exists():
        print("Please specify path of the binary to test the crashes with (e.g. compiled with ASAN)")
        exit()
    
    print("Processing crashes...")
    print(f"Using binary: {crashing_binary}")
    crash_res_file = Path(base_dir / "results" / "timestamp_to_crash.txt")
    res_crash_dir : Path = crash_res_file.parent / "crashes"
    crash_report_dir : Path = res_crash_dir / "reports"
    ts_to_crash : list[tuple]  = get_crashes(base_dir, res_crash_dir)
    
    result_dir : Path = base_dir / "results"
    result_dir.mkdir(exist_ok=True)
    if not crash_res_file.exists():     
        print("Saving crashes")
        with open(crash_res_file,"w") as fd:
            for ts, crash in ts_to_crash:
                fd.write(f"{ts},{crash}\n")
    else:
        print("crash results already exists!")
        
    crashes : list[Path] = res_crash_dir.iterdir()
    crash_report_dir.mkdir(exist_ok=True)
    
    for i, crash in enumerate(crashes):
        if crash.is_dir():
            continue
        args_list = shlex.split(target_args)
        target_args_w_input = [arg.replace("@@", str(crash)) for arg in args_list]
        test_crash_cmd = [str(crashing_binary), *target_args_w_input]
        print(f"Crash cmd:\n\t{test_crash_cmd}")
        res = execute_cmd(test_crash_cmd, capture_output = True)
        crash_report_file : Path = crash_report_dir / f"crash_{i:03d}_{crash.name}.txt"
        with open(crash_report_file.as_posix(), "w") as fd:
            fd.write(res.stderr.decode("utf-8"))
        print(f"Generated crash report:\n\t{crash_report_file}")
        

def process_trial(trial : int, working_args : Dict[str, Any], base_dir : Path):
    print(f"Processing trial: {trial} on base dir:{base_dir}")

    return llvm_cov(working_args, str(trial), base_dir)

def log(log_value : str, log_file = "iterator_trial.txt"):
    print(log_value)
    with open(log_file, "a") as fd:
            fd.write(f"{log_value}\n")

def run_calc(working_args : Dict[str, Any], all_jobs : list[tuple[Path, int]], chunk_size : int = 20):

    with concurrent.futures.ProcessPoolExecutor(max_workers=chunk_size) as executor:
        futures_list = [executor.submit(process_trial, trial, working_args, base_dir) for base_dir, trial in all_jobs]
        concurrent.futures.wait(futures_list, return_when=concurrent.futures.FIRST_EXCEPTION)


def run_calc_and_periodic_plot(executor, main_function, periodic_function, base_dir: Path, fuzzer_names : set[str], main_args, interval_seconds=60):
    stop_event = threading.Event()

    # Start the periodic function in a separate thread
    #periodic_thread = threading.Thread(target=periodic_function, args=(stop_event, interval_seconds, fuzzer_names, base_dir))
    #periodic_thread.start()

    try:
        # Run the main function using the ProcessPoolExecutor
        with concurrent.futures.ThreadPoolExecutor() as thread_executor:
            future = thread_executor.submit(main_function, *main_args)
            concurrent.futures.wait([future], return_when=concurrent.futures.FIRST_EXCEPTION)

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
        #periodic_thread.join()
        
        # create a gif from incremental files
        #gif_up()

def init(fuzzer_names, working_args : Dict[str, Any]) -> list[Path, int]:
    fuzzer_info = []
    print("found the following fuzzers")
    print(fuzzer_names)

    num_trials = working_args["trials"]
    work_dir = working_args["work_dir"]
    all_jobs = []

    for i, fuzzer_name in enumerate(fuzzer_names):
        print(f"Fuzzer: {fuzzer_name}")
        base_dir = work_dir / Path("coverage_analysis") / fuzzer_name
        mount_corpus(working_args, base_dir, fuzzer_name, umount=True)
        create_directory_structure(base_dir, skip_corpus)
        
        mount_corpus(working_args, base_dir, fuzzer_name)
        fuzzer_info.append(base_dir)
        all_jobs.extend(list(zip([base_dir] * num_trials, range(num_trials))))
        print(f"Done: {i+1}/{len(fuzzer_names)}\n")
        
    return all_jobs

def parse_arguments(raw_args: Optional[Sequence[str]]) -> Namespace:
    parser: ArgumentParser = ArgumentParser(description="Controller for AFL++ restarting instances")
    
    parser.add_argument("--work_dir", type=Path, default=None, help="Path where to store the results")
    parser.add_argument("--corpus", type=Path, default=None, help="Path to corpus base (results of all fuzzers and all trials)")
    parser.add_argument("--trials", type=int, default=10, help="Number of trials")
    parser.add_argument("--target", type=str, default="objdump", help="Target name")
    parser.add_argument("--cov_bin", type=Path, default="", help="Path to llvm compiled coverage binary")
    parser.add_argument("--trial_idf", type=str, default="", help="Identifier for trial directories e.g. trial_[0-9]*")
    parser.add_argument("--fuzzer_names", type=str, default="", help="Fuzzer names in quotes")
    parser.add_argument("--target_args", type=str, default="", help="Target arguments, use quotes")
    parser.add_argument("--fuzzer_type", type=str, default="afl", help="Fuzzer type eg afl-based (afl) or libafl-based (libafl")
    parser.add_argument("--calc", action="store_true", default=False, help="Calculate coverage")
    parser.add_argument("--res", action="store_true", default=False, help="Print results")
    parser.add_argument("--plot", action="store_true", default=False, help="Plot results")
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
    parser.add_argument("--pformat", type=str, default="pdf", help="Save plots as FORMAT")
    parser.add_argument("--crash_binary", type=Path, help="Path to binary to test crashes (e.g. compiled with ASAN)")
    parser.add_argument("--accuracy", type=float, default=0.5, help="Accuracy of the line coverage plot [0.0-1.0] (0: fastest / no useful line plot, 1: most accurate line plot)")
    parser.add_argument("--plot_desc", type=str, default="", help="Description for the plot")
    parser.add_argument("--color_file", type=Path, default=None, help="Path to a file containing fuzzer names and colors")
    parser.add_argument("--other_testcases", type=Path, default="", help="Other testcase dir (absolute path or relative to queue dir), e.g. '.state/XXXX'")
    parser.add_argument("--annotation-file", type=Path, default=None, help="Annotation file for plotting, e.g. to add identifiers to the plot (median run)")

    if raw_args is None and len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    return parser.parse_args(raw_args)


def main(raw_args: Optional[Sequence[str]] = None):
    global skip_corpus, show_bands, regex, num_trials, llvm_version, all_jobs_len, accuracy, other_testcase_dir
    
    args: Namespace = parse_arguments(raw_args)
    working_args: dict = gen_arguments(args)
    skip_corpus = args.skip
    show_bands = args.show_bands
    regex = args.regex
    num_trials = args.trials
    plot_desc = args.plot_desc
    other_testcase_dir = args.other_testcases
    
    if args.accuracy < 0.0 or args.accuracy > 1.0:
        print("Accuracy must be between 0 and 1.0")
        exit()
    accuracy = args.accuracy
    
    # check which version of llvm is installed
    llvm_version = subprocess.run(["llvm-config", "--version"], capture_output=True).stdout.decode("utf-8").split(".")[0]
    
    if shutil.which("llvm-cov-" + llvm_version) == None:
        print(f"llvm not found!")
        exit()        

    if skip_corpus:
        print("Skipping corpus copy!!\nI hope you know what you are doing and you have the correct corpus here... 5sec to think about")
        time.sleep(5)

    if args.fuzzer_names != "":
        fuzzer_names = args.fuzzer_names.split(",")
    else:
        fuzzer_names = get_all_fuzzer(working_args, cstrip=args.strip)
    
    if args.regcheck:
        print("found the following fuzzers")
        print(fuzzer_names)
        exit()
    
    all_jobs = []
    if args.crashes or args.calc:
        all_jobs = init(fuzzer_names, working_args)
        
    if args.crashes:
        for fuzzer_name in fuzzer_names:
            process_crashes(Path("coverage_analysis")  / fuzzer_name, working_args)

    if args.calc:
        print(f"All jobs: {len(all_jobs)}")
        all_jobs_len = len(all_jobs)
        # testing
        if args.testing:
            for base_dir, trial in all_jobs:
                process_trial(trial, working_args, base_dir)
        else:    
            main_args = (working_args, all_jobs, args.parallel_trials)
            base_dir = working_args["work_dir"] / Path("coverage_analysis")
            run_calc_and_periodic_plot(concurrent.futures.ProcessPoolExecutor(), run_calc, interval_plot_thread, base_dir, fuzzer_names, main_args, interval_seconds=180)
                
        print("All trials processed.")
        
    for i, fuzzer_name in enumerate(fuzzer_names):
        print(f"Fuzzer: {fuzzer_name}")
        work_dir = working_args["work_dir"]
        base_dir = work_dir / Path("coverage_analysis") / fuzzer_name
        mount_corpus(working_args, base_dir, fuzzer_name, umount=True)

    if args.res:
        print("not implemented")

    if args.plot:
        fuzzer_colors = {}
        
        if args.color_file and args.color_file.exists():
            print(f"Using color file: {args.color_file}")
            with open(args.color_file, "r") as fd:
                fuzzer_colors = json.load(fd)                            
        
        print(fuzzer_names)
        base_dir = args.work_dir / Path("coverage_analysis")
        plotting(set(fuzzer_names), base_dir=base_dir, plot_crashes=args.crashes, save_format = args.pformat, plot_desciption=plot_desc, fuzzer_colors=fuzzer_colors, annotation_file=args.annotation_file)

    if args.gif:
        gif_up()


if __name__ == "__main__":
    main()
