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
from typing import Any, Dict, List, Optional, Sequence
import re
import time
import matplotlib.pyplot as plt
import numpy as np


CONTAINER_NAME = "llvm_cov_analysis"
skip_raw = False
mode = ""

def get_testcases(corpus_path: Path) -> list[Path]:
    #print(f"Gathering testcases from {corpus_path.as_posix()}")
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
    if start_time_file.exists:
        with open(start_time_file.as_posix(),"r") as fd:
            starttime = fd.readline().split(".")[0]
        if starttime != "":
            return starttime
        else:
            print(f"Error: no starttime found -- {fuzzer_stats_path} / {start_time_file}")
    return ""


def get_all_fuzzer(working_args, regex="[a-z]*", cstrip = ""):
    corpus_base_path = working_args["corpus_path"]
    mode = working_args["mode"]

    all_fuzzers : list[Path] = list(corpus_base_path.iterdir())
    print(list(fuzzer_entry.name for fuzzer_entry in all_fuzzers))
    
    fuzzer_names : set = set(match.group(0).strip(cstrip) for fuzzer_entry in all_fuzzers if (match := re.search(regex, fuzzer_entry.name)) is not None)

    return fuzzer_names


def copy_corpus(working_args, base_dir : Path, fuzzer_name: str) -> None:
    
    corpus_base_path = working_args["corpus_path"]
    mode = working_args["mode"]

    trial_paths : list[Path] = list(corpus_base_path.glob(f"*{fuzzer_name}*"))

    if len(trial_paths) == 0:
        # fuzzbench trials
        print("Found fuzzbench trials")
        trial_paths : list[Path] = list(corpus_base_path.glob(f"trial*"))

    for trial_id, trial_path in enumerate(trial_paths):
        print(f"creating trial: trial_{trial_id}")
        (base_dir / "tmp" / "full_corpus" / f"trial_{trial_id}").mkdir()
        (base_dir / "profraw_files" / f"trial_{trial_id}").mkdir(exist_ok=True, parents=True)
        (base_dir / "profdata_files" / f"trial_{trial_id}").mkdir(exist_ok=True, parents=True)
        
        queue_path : Path = Path()
        dest_path = Path(base_dir / "tmp" / "full_corpus" / f"trial_{trial_id}" / "default")

        if mode == "afl":
            #print(trial_path)
            if Path(trial_path / "default").exists(): 
                queue_path = trial_path / "default"
            elif Path(trial_path / "queue").exists():
                queue_path = trial_path
            else: 
                queue_paths = list(trial_path.glob("**/queue/"))
                if len(queue_paths) > 1:
                    print(f"found more than 1 queue - assuming mode sileo!")
                    mode = "sileo"
                else:
                    queue_path = queue_paths[0].parent

            #queue_path = list(trial_path.glob("*/default/"))[0] 
        if mode == "sileo":
            # print("in sileo mode")
            # print(trial_path)
            run_paths : list[Path] = list(trial_path.glob(f"**/run_*"))
            for run in run_paths:
                dest_path = Path(base_dir / "tmp" / "full_corpus" / f"trial_{trial_id}" / run.name)
                if run.is_dir():
                    shutil.copytree(run, dest_path)
            mode = "afl"
            continue
        
        print(f"Queue path: {queue_path}")
        shutil.copytree(queue_path, dest_path)


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

def llvm_cov(working_args, trial: str, base_dir: Path, fuzzer_mode : str = "afl") -> tuple[bool, Path]:

    trial = f"trial_{trial}"
    full_corpus : Path = base_dir / "tmp" / "full_corpus"
    profraw_dir : Path = base_dir / "profraw_files" / trial
    profdata_dir : Path = base_dir / "profdata_files" / trial
    target_bin = working_args["cov_bin"]
    target_args = working_args["target_args"]

    print("Starting llvm coverage analysis")

    testcases_to_starttime: list[tuple] = []
    starttime = ""
    testcases = []
    if fuzzer_mode == "afl":
        if Path(full_corpus / trial / "default" / "queue").exists():
            testcases: list[Path] = get_testcases(full_corpus / trial / "default" / "queue")
            starttime: str = get_starttime(full_corpus / trial / "default" / "fuzzer_stats")
        elif Path(full_corpus / trial / "queue").exists():
            testcases: list[Path] = get_testcases(full_corpus / trial / "queue")
            starttime: str = get_starttime(full_corpus / trial / "fuzzer_stats")
        else:
            print("Something went wrong, no queue directory found - testing sileo")
            fuzzer_mode = "sileo"
        
        if starttime != "":
            testcases_to_starttime = list(zip([starttime] * len(testcases), testcases))
    
    if fuzzer_mode == "sileo":
        runs = list((full_corpus / trial).iterdir())
        run_to_startime: dict[str,str] = {}
        testcases = []
        for run_id in range(0, len(runs)):
            testcases = get_testcases(full_corpus / trial / f"run_{run_id}" / "default" / "queue")
            starttime = get_starttime(full_corpus / trial / f"run_{run_id}" / "default" / "fuzzer_stats")

            testcases_to_starttime.extend(list(zip([starttime] * len(testcases), testcases)))
            run_to_startime.update({f"run_{run_id}":starttime})

    if not skip_raw:
        print(f"Generating profraw data from testcases... ({trial})")
        cov_times = []

        for i, testcase_to_starttime in enumerate(testcases_to_starttime):
            starttime, testcase = testcase_to_starttime

            if i % 1000 == 0:
                print(f"Processing Testcase {trial}:\t {i}/{len(testcases_to_starttime)}")
            testcase_time = testcase.name.split(",time:")[1].split(",")[0]
            cov_time = int(starttime) + int(testcase_time) // 1000
            cov_times.append(cov_time)
            profraw_file = f"{profraw_dir}/llvm_{i:08d}_ts:{cov_time}.profraw"
            # print(f"profraw_file:",profraw_file)
            os.environ["LLVM_PROFILE_FILE"] = profraw_file
            llvm_target_cmd = f"{target_bin} {target_args} {testcase}"

            execute_cmd(llvm_target_cmd.split(" "))
        print(f"\nGenerating profraw files done ({trial})!")

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

    print(f"Merging and exporting data profdata... ({trial})")

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

        #print(f"Running command ({trial}): {llvm_profdata_cmd}")
        print(f"Processing (merge profdata) ({trial}): {id}/{len(profdata_files)} -- {round(id / len(profdata_files)*100,2)}%")
        
        execute_cmd(llvm_profdata_cmd.split(" "))
        llvm_export_cmd = f"llvm-cov-14 export -format=text -region-coverage-gt=0 -skip-expansions {target_bin} -instr-profile={profdata_file_final}"
        #print(f"Running export command ({trial}): {llvm_export_cmd}")
        res = execute_cmd(llvm_export_cmd.split(" "), capture_output=True)
        report_data = json.loads(res.stdout)
        
        branch_count = calculate_cov_branches(report_data)
        #branch_count = get_branches_covered(report_data)
        
        timestamp_to_b_covered.append((timestamp, branch_count))

        with open(f"{profdata_dir}/timestamp_to_b_covered.txt","a") as fd:
                fd.write(f"{timestamp},{branch_count}\n")

        if len(res.stderr) > 0:
            print(f"Seems an error occured, see {profdata_dir}/llvm-cov.stderr for more information")
            with open(f"{profdata_dir}/llvm-cov.stderr", "wb") as fd:
                fd.write(res.stderr)
        with open(f"{profdata_dir}/llvm-cov.json", "wb") as fd:
            fd.write(res.stdout)

        profdata_file.unlink()
    print(f"Export done ({trial})")

    # cleanup to save space
    clean_up(profraw_dir)
    clean_up(full_corpus)

    return True, base_dir


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
    execute_cmd(llvm_profdata_cmd.split(" "))

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

def execute_cmd(cmd : List[str], capture_output=True):
    #print(f"command: " + " ".join(cmd))
    res = subprocess.run(cmd, capture_output=capture_output)
    #print(res.stdout)
    #print(res.stderr)

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

def get_a_clean_dir(dir_path : Path):
    print(f"Init directory structure: {dir_path}")
    if dir_path.exists():
        shutil.rmtree(dir_path)
    dir_path.mkdir(parents=True)
    return dir_path

def create_directory_structure(base_dir: Path):

    tmp_dir : Path = base_dir / "tmp"
    tmp_corpus_dir : Path  = tmp_dir  / "full_corpus"
    profraw_dir = base_dir / "profraw_files"

    get_a_clean_dir(tmp_dir)
    get_a_clean_dir(profraw_dir)
    get_a_clean_dir(tmp_corpus_dir)


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
        cov_bin_path : Path = args.cov_bin
        
    trials : int = args.trials
    target_name : str = args.target

    return {"mode" : mode, "corpus_path": corpus_path, "cov_bin": cov_bin_path, "trials" : trials, "target_name": target_name, "target_args": args.target_args}


def calc_percentile(mode):
    import numpy as np

    base_dir = Path("coverage_analysis") / mode
    ts_to_branch = []

    profdata_dir : Path = base_dir / "profdata_files"
    trials : list[Path] = list(profdata_dir.iterdir())
    trial_results_branches = []
    trial_results_ts = []
    for trial in trials:
        print(f"processing: {trial.name}")
        ts_to_branch_file : Path =  profdata_dir / trial.name / "timestamp_to_b_covered.txt"
        with open(ts_to_branch_file,"r") as fd:
            ts_to_branch = fd.readlines()

        ts_list = []
        branches_covered_list = []
        starttime = None
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
                if ts + 1 < ts_next:
                    branches_covered_list.append(int(branches_covered))
                    ts_list.append(ts_relative)
                    ts_relative += 1
                    ts += 1
                else:
                    branches_covered_list.append(int(branches_covered))
                    ts_list.append(ts_relative)
                    ts +=1
                    break
            ts_relative += 1
        
        # fill the array with the last branch value
        while ts_relative < 86400 or ts_relative > 86400:
            if ts_relative < 86400:
                ts_relative += 1
                ts_list.append(ts_relative)
                branches_covered_list.append(branches_covered_list[-1])
            else:
                ts_relative -= 1
                ts_list.pop()
                branches_covered_list.pop()

        trial_results_branches.append(branches_covered_list)
        trial_results_ts.append(ts_list)

    all_trial_branches = []
    for idx in range(len(trial_results_branches[0])):
        value_series = []
        for trial_idx in range(len(trial_results_branches)):
            value_series.append(trial_results_branches[trial_idx][idx])  
        all_trial_branches.append(value_series)

    lower = []
    upper = []

    for values in all_trial_branches:
        interval = sorted(values)[2:8]
        min_val = interval[0]
        max_val = interval[-1]
        lower.append(min_val)
        upper.append(max_val)
    median = np.median(all_trial_branches, axis=1)

    return median, lower, upper


def plot_coverage_to_time(_mode):
   
    print("plotting data")
    
    if _mode == "all":
        modes = {"afl", "sileo"}
    else:
        modes = {_mode}

    for mode in modes:
        median, lower, upper = calc_percentile(mode)

        plt.fill_between(np.arange(len(median)), lower, upper, alpha = 0.5)

        plt.plot(np.arange(len(median)),median, alpha = 0.5, label=f"Median - {mode}")
    print(_mode)
    plt.xlabel("Time (s)")
    plt.ylabel("Number of branches covered")
    plt.legend()
    plt.savefig(f"zz_plot_{_mode}.png")

def random_rgb_color():
    return tuple(np.random.rand(3,))

def color_difference(color1, color2):
    return sum((c1 - c2) ** 2 for c1, c2 in zip(color1, color2))

def is_color_different(color, used_colors, threshold=0.2):
    for used_color in used_colors:
        if color_difference(color, used_color) < threshold:
            return False
    return True


def plot_while_calc(regex = "[0-9].[0-9]*c"):
    base_dir = Path("coverage_analysis") 

    if not Path("plots").exists():
        Path("plots").mkdir()

    all_ts_data_paths: list[Path] = sorted(list(base_dir.glob("./**/timestamp_to_b_covered.txt")))
    print(f"data paths: {all_ts_data_paths}")
    fuzzer_names = set()
    for ts_data_path in all_ts_data_paths:
        name_match = re.search("[0-9].[0-9]*c", ts_data_path.as_posix())
        # print(f"name match: {name_match}")
        if name_match != None:
            if name_match in fuzzer_names:
                continue
            else:
                fuzzer_name = name_match.group(0)
                fuzzer_names.add(fuzzer_name)
                print(f"found stats for {fuzzer_name}")
        else:
            fuzzer_name = ""
            continue

    fig, ax = plt.subplots()
    used_colors = set()

    for fuzzer_name in fuzzer_names:
        # all trial paths of fuzzer with name...
        # coverage_analysis_old/afl/profdata_files/trial_0/timestamp_to_b_covered.txt
        all_trial_paths = sorted(list(base_dir.glob(f"./{fuzzer_name}/profdata_files/*/timestamp_to_b_covered.txt")))

        fuzzer_color = random_rgb_color()

        # Check if the color is sufficiently different from used colors
        while not is_color_different(fuzzer_color, used_colors, threshold=0.2):
            fuzzer_color = random_rgb_color()

        for ts_to_branch_file in all_trial_paths:
            ts_to_branch = []
            with open(ts_to_branch_file.as_posix(),"r") as fd:
                ts_to_branch = fd.readlines()
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
                    if ts + 1 < ts_next:
                        branches_covered_list.append(int(branches_covered))
                        ts_list.append(ts_relative)
                        ts_relative += 1
                        ts += 1
                    else:
                        branches_covered_list.append(int(branches_covered))
                        ts_list.append(ts_relative)
                        ts +=1
                        break
                ts_relative += 1

            ax.plot(ts_list, branches_covered_list, color=fuzzer_color, alpha = 0.5, label=f"{fuzzer_name}")

    # Add a legend for each unique color
    handles, labels = plt.gca().get_legend_handles_labels()
    by_label = dict(zip(labels, handles))
    plt.legend(by_label.values(), by_label.keys())

    plt.xlabel("Time (s)")
    plt.ylabel("Number of branches covered")
    plt.show()
    plt.savefig(f"plots/all.png")
    

def parse_arguments(raw_args: Optional[Sequence[str]]) -> Namespace:
    parser: ArgumentParser = ArgumentParser(description="Controller for AFL++ restarting instances")
    
    parser.add_argument("--corpus", type=Path, default=None, help="Path to corpus base")
    parser.add_argument("--trials", type=int, default=10, help="Number of trials")
    parser.add_argument("--target", type=str, default="objdump", help="Target name")
    parser.add_argument("--cov_bin", type=Path, default=None, help="Path to llvm compiled coverage binary")
    parser.add_argument("--mode", type=str, default="afl", help="Set mode sileo | afl")
    parser.add_argument("--target_args", type=str, default="", help="Target arguments, use quotes")
    parser.add_argument("--calc", action="store_true", default=False, help="Calculate coverage")
    parser.add_argument("--res", action="store_true", default=False, help="Print results of mode")
    parser.add_argument("--plot", action="store_true", default=False, help="Plot results of mode")
    parser.add_argument("--cplot", action="store_true", default=False, help="Plot results of mode")
    parser.add_argument("--skip", action="store_true", default=False, help="Skip raw processing")
    parser.add_argument("--regex", type=str, default="", help="Regex to get specific filename identifier: e.g.\n\t\tdirectory: afl_0 afl_1 ...\n\t\tregex: afl_[0-9]*")
    parser.add_argument("--strip", type=str, default="", help="Strip the resulting fuzzer names by given character")
    parser.add_argument("--threads", type=int, default=80, help="Maximum number of threads")
    
    return parser.parse_args(raw_args)


def process_trial(trial, working_args, base_dir):
    print(f"Processing trial: {trial} on base dir:{base_dir}")
    return llvm_cov(working_args, str(trial), base_dir)


def main(raw_args: Optional[Sequence[str]] = None):
    global skip_raw, mode
    

    args: Namespace = parse_arguments(raw_args)


    working_args: dict = gen_arguments(args)
    mode = working_args["mode"]
    skip_raw = args.skip
    
    # [0-9]\.[0-9]*c

    fuzzer_info = []

    if args.calc:
        if not skip_raw:
            fuzzer_names = get_all_fuzzer(working_args,regex=args.regex, cstrip=args.strip)
            print("found the following fuzzers")
            print(fuzzer_names)

            num_trials = working_args["trials"]
            all_jobs = []

            for fuzzer_name in fuzzer_names:
                print(fuzzer_name)
                base_dir = Path("coverage_analysis") / fuzzer_name
                create_directory_structure(base_dir)
                copy_corpus(working_args, base_dir, fuzzer_name)
                fuzzer_info.append(base_dir)
                all_jobs.extend(list(zip([base_dir] * num_trials, range(num_trials))))

            total_runs = len(fuzzer_names) * num_trials
            num_parallel_fuzzers = args.threads // num_trials

            print(f"Number of parallel fuzzers: {num_parallel_fuzzers}")

            #for base_dir, trial in all_jobs:
            #    process_trial(0, working_args, base_dir)
            
            futures = {}
            with concurrent.futures.ProcessPoolExecutor(max_workers=args.threads) as executor:
                try:
                    futures = {executor.submit(process_trial, trial, working_args, base_dir) for base_dir, trial in all_jobs}
                    #concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_EXCEPTION)
                    for completed_future in concurrent.futures.as_completed(futures, timeout=1.0):
                        # Check if the completed future is an exception
                        if completed_future.exception():
                            print(f"Future raised an exception: {completed_future.exception()}")

                        # Handle the result or do additional processing
                        result, f_base_dir = completed_future.result()
                        if result:
                            print(f"Result: {result, f_base_dir}")
                            
                        # Run the plotting every five minutes 
                        if time.time() % 300 == 0:
                            plot_while_calc()


                except KeyboardInterrupt:
                    print("Stopping processes...")
                    executor.shutdown(wait=False, cancel_futures=True)

        print("All trials processed.")
    
    if args.res:
        if working_args["mode"] == "all":
            base_dir = Path("coverage_analysis") / "afl"
            get_results(base_dir)
            print("------------------------------------")
            base_dir = Path("coverage_analysis") / "sileo"
            get_results(base_dir)

    if args.plot:
        plot_coverage_to_time(args.mode)

    if args.cplot:
        plot_while_calc(args.regex)


if __name__ == "__main__":
    main()
