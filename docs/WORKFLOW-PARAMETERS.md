# Workflow Parameters
Adding parameters in the Git commit log can control the workflow.

## --filter
This parameter specifies which workflows to run, instead of running all of them.
The command format is: `--filter=[flow1][flow2][flow...]` ,
and it supports setting multiple workflows, with names matching the filename of the yml file.

## --valgrind
Setting this parameter will cause the test program to be run with `valgrind`.

```shell
git commit -m "commit message --filter=[core][unit] --valgrind"
```

## --asan
Setting this parameter will cause the test program to be run with `ASAN`.
