# selinux-denial

Uploads on example.com fail with Permission denied although Unix permissions are fine: SELinux (Enforcing) labels uploads/ user_home_t. Fix: semanage fcontext + restorecon with httpd_sys_rw_content_t, never setenforce 0.
