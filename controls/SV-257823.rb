control 'SV-257823' do
  title 'RHEL 9 must be configured so that the cryptographic hashes of system files match vendor values.'
  desc 'The hashes of important files like system executables should match the information given by the RPM database. Executables with erroneous hashes could be a sign of nefarious activity on the system.'
  desc 'check', %q(The following command will list which files on the system have file hashes different from what is expected by the RPM database:

 $ rpm -Va --noconfig | awk '$1 ~ /..5/ && $2 != "c"' 

If there is output, this is a finding.)
  desc 'fix', %q(Given output from the check command, identify the package that provides the output and reinstall it. The following trimmed example output shows a package that has failed verification, been identified, and been reinstalled:

$ rpm -Va --noconfig | awk '$1 ~ /..5/ && $2 != "c"'
S.5....T.    /usr/bin/znew
$ sudo dnf provides /usr/bin/znew
[...]
gzip-1.10-8.el9.x86_64 : The GNU data compression program
[...]
$ sudo dnf reinstall gzip
[...]
$ rpm -Va --noconfig | awk '$1 ~ /..5/ && $2 != "c"'
[no output])
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61564r925454_chk'
  tag severity: 'medium'
  tag gid: 'V-257823'
  tag rid: 'SV-257823r925456_rule'
  tag stig_id: 'RHEL-09-214030'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61488r925455_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
