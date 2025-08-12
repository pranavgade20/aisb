Exercise 1.5
The cell that creates directories sometimes needs to be rerun (kernel restarts, etc) and it should specify exist_ok=True in order not to try recreating existing files.

Exercise 1.1-1.6
It would be awesome if the last part (1.6) was described in the beginning as well so that we know what is the end goal while working on individual smaller parts. This applies to the most of such exercises with multiple steps.

Exercises 2-3?
TARGET_ARCH, TARGET_VARIANT were missing from test files

Exercise 3.3
Tests were missing create_cgroup function

Exercise 3.5
It works even without step 2 in the pseudocode (the main improvement from the previous exercise).

Exercise 4.1
run_in_cgroup_chroot_namespaced missing as an argument in the test.
Also, whenever we had to make changes in test file, we also had to reload the kernel and execute all the cells.
