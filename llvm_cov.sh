#!/bin/bash

# use in a docker container where $TARGET_BIN and $TARGET_ARGS are set or set them via bash variables
# fuzzing corpus (of all fuzzers) is mounted as /fuzz (-v $(pwd)/corpus:/fuzz)
# coverage output directory is mounted as /work (-v $(pwd)/coverage_out:/work)

# TARGET_BIN=/out/target_cov_binary
# TARGET_ARGS="@@"

TARGET_NAME=bloaty
repetitions=10
# cores for cov calculation
cores=380
# number of parallel processed trials
parallel_trials=60

python3.10 /calculate_llvm_cov.py --work_dir /work --corpus /fuzz --trials "$repetitions" --target "$TARGET_NAME" --regex "aflpp-[a-zA-Z0-9.]*.*" --threads $cores --parallel_trials $parallel_trials --strip "-" --trial_idf "run-[0-9]*" --calc --plot --accuracy 0.99 --plot_desc "AFL++ vs. AFL-XYZ" --cov_bin "$TARGET_BIN" --target_args "$TARGET_ARGS"
