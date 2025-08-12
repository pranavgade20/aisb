In 4.1 (create c_group and namespace), the solution code will have the parent continue the child process regardless of if the add_process_to_c_group is successful. This is a pretty majority security flaw, it should kill the child process upon failure.

For the solution of create_bridge_interface (5.1), the "exec_sh("ip link del bridge0", check_retcode=False)" line should be indented to be within the if statement. 

Also, the w2d2 file needs to be fixed. I needed to add the exec_sh() function. Also, some of the function calls within the test file are missing the actual function they are supposed to be testing. 
