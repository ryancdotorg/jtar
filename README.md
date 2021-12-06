# jtar
Tool for creating tar files from ND-JSON manifests.

```
usage: jtar [-h] [-a | -z | -j | -J | --no-auto-compress | -g]
            [--dirs-first | --dirs-last | --dirs-omit] [-T FILE]
            [-d KEY=VALUE] [-C DIR] [-f FILE]
            [FILE [FILE ...]]

Generate a tar file from a JSON manifest.

positional arguments:
  FILE                  input filename(s)

optional arguments:
  -h, --help            show this help message and exit
  -a, --auto-compress   compress output based on file suffix (default)
  -z                    compress output with gzip
  -j, --bzip2           compress output with bzip2
  -J, --xz              compress output with xz
  --no-auto-compress    do not automatically compress output file based on
                        suffix
  -g, --generate        generate a JSON manifest from tar file
  --dirs-first          keep first instance of directory (default)
  --dirs-last           keep last instance of directory
  --dirs-omit           omit directories
  -T FILE               read template definitions from FILE
  -d KEY=VALUE, --define KEY=VALUE
                        define template variable KEY as VALUE
  -C DIR, --directory DIR
                        treat sources as relative to DIR
  -f FILE               output filename
```
