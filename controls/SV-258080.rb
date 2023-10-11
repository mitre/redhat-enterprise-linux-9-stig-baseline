control 'SV-258080' do
  title 'RHEL 9 must configure SELinux context type to allow the use of a nondefault faillock tally directory.'
  desc 'Not having the correct SELinux context on the faillock directory may lead to unauthorized access to the directory.'
  desc 'check', %q(Verify the location of the nondefault tally directory for the pam_faillock module with the following command:

Note: If the system does not have SELinux enabled and enforcing a targeted policy, or if the pam_faillock module is not configured for use, this requirement is Not Applicable.

$ grep 'dir =' /etc/security/faillock.conf

dir = /var/log/faillock

Check the security context type of the nondefault tally directory with the following command:

$ ls -Zd /var/log/faillock

unconfined_u:object_r:faillog_t:s0 /var/log/faillock

If the security context type of the nondefault tally directory is not "faillog_t", this is a finding.)
  desc 'fix', 'Configure RHEL 9 to allow the use of a nondefault faillock tally directory while SELinux enforces a targeted policy.

Create a nondefault faillock tally directory (if it does not already exist) with the following example:

$ sudo mkdir /var/log/faillock

Update the /etc/selinux/targeted/contexts/files/file_contexts.local with "faillog_t" context type for the nondefault faillock tally directory with the following command:

$ sudo semanage fcontext -a -t faillog_t "/var/log/faillock(/.*)?"

Next, update the context type of the nondefault faillock directory/subdirectories and files with the following command:

$ sudo restorecon -R -v /var/log/faillock'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61821r926225_chk'
  tag severity: 'medium'
  tag gid: 'V-258080'
  tag rid: 'SV-258080r926227_rule'
  tag stig_id: 'RHEL-09-431020'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-61745r926226_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
