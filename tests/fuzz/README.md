# Fuzzing target for cryptsetup project

This directory contains experimental targets for fuzzing testing.
It can be run in the OSS-Fuzz project but also compiled separately.

# Requirements

Fuzzers us address sanitizer. To properly detect problems, all
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

# Buid Docker image and fuzzers

You can also run OSS-Fuzz in a Docker image, use these commands
to prepare fuzzers:
```
sudo python3 infra/helper.py build_image cryptsetup
sudo python3 infra/helper.py build_fuzzers cryptsetup
```
On SELinux systems also add:
```
sudo chcon -Rt svirt_sandbox_file_t build/
```
# Run LUKS2 fuzzer
```
sudo python infra/helper.py run_fuzzer --corpus-dir build/corpus/cryptsetup/crypt2_load_fuzz/ --sanitizer address cryptsetup crypt2_load_fuzz -jobs=8 -workers=8
```
# Rebuild fuzz targets for coverage
```
sudo python infra/helper.py build_fuzzers --sanitizer coverage cryptsetup
```
# Generate coverage report
```
sudo python infra/helper.py coverage cryptsetup --no-corpus-download --fuzz-target crypt2_load_fuzz
```
