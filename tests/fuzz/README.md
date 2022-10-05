# Fuzzing target for cryptsetup project

This directory contains experimental targets for fuzzing testing.
It can be run in the OSS-Fuzz project but also compiled separately.

# Requirements

Fuzzers use address sanitizer. To properly detect problems, all
important libraries must be compiled statically with sanitizer enabled.

Compilation requires *clang* and *clang++* compilers (gcc is not
supported yet).

# Standalone build

The script `oss-fuzz-build.sh` can be used to prepare the tree
with pre-compiled library dependencies.
We use upstream git for projects, which can clash with locally
installed versions. The best is to use only basic system installation
without development packages (script will use custom include, libs,
and pkg-config paths).

# Build Docker image and fuzzers

You can also run OSS-Fuzz in a Docker image, use these commands
to prepare fuzzers:
```
sudo python3 infra/helper.py build_image cryptsetup
sudo python3 infra/helper.py build_fuzzers cryptsetup
```
On SELinux systems also add (https://github.com/google/oss-fuzz/issues/30):
```
sudo chcon -Rt svirt_sandbox_file_t build/
```

# Run LUKS2 fuzzer
`FUZZER_NAME` can be one of: `crypt2_load_fuzz`, `crypt2_load_proto_fuzz`, `crypt2_load_proto_plain_json_fuzz`
```
FUZZER_NAME="crypt2_load_proto_plain_json_fuzz"
sudo mkdir -p build/corpus/cryptsetup/$FUZZER_NAME
sudo python infra/helper.py run_fuzzer --corpus-dir build/corpus/cryptsetup/$FUZZER_NAME/ --sanitizer address cryptsetup $FUZZER_NAME '-jobs=8 -workers=8'
```

The output of the parallel threads will be written to `fuzz-<N>.log` (where `<N>` is the number of the process).
You can watch it using e.g.:
```
tail -f build/out/cryptsetup/fuzz-*
```

Optionally, you can use experimental `fork` mode for parallelization and the output will be displayed directly on the terminal:
```
sudo python infra/helper.py run_fuzzer --corpus-dir build/corpus/cryptsetup/$FUZZER_NAME/ --sanitizer address cryptsetup $FUZZER_NAME '-fork=8 '
```

# Rebuild fuzz targets for coverage
```
sudo python infra/helper.py build_fuzzers --sanitizer coverage cryptsetup
```

# Generate coverage report
```
sudo python infra/helper.py coverage cryptsetup --no-corpus-download --fuzz-target $FUZZER_NAME
```

# Further information
For more details, you can look into the [Using fuzzing for Linux disk encryption tools](https://is.muni.cz/th/bum03/?lang=en) thesis.
