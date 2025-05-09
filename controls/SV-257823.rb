control 'SV-257823' do
  title 'RHEL 9 must be configured so that the cryptographic hashes of system files match vendor values.'
  desc 'The hashes of important files such as system executables should match the information given by the RPM database. Executables with erroneous hashes could be a sign of nefarious activity on the system.'
  desc 'check', %q(Verify that RHEL 9 is configured so that the cryptographic hashes of system files match vendor values.
 
List files on the system that have file hashes different from what is expected by the RPM database with the following command:

$ sudo rpm -Va --noconfig | awk '$1 ~ /..5/ && $2 != "c"' 

If there is output, this is a finding.)
  desc 'fix', %q(Configure RHEL 9 so that the cryptographic hashes of system files match vendor values.

Given output from the check command, identify the package that provides the output and reinstall it. The following trimmed example output shows a package that has failed verification, been identified, and been reinstalled:

$ sudo rpm -Va --noconfig | awk '$1 ~ /..5/ && $2 != "c"'
S.5....T.    /usr/bin/znew

$ sudo dnf provides /usr/bin/znew
[...]
gzip-1.10-8.el9.x86_64 : The GNU data compression program
[...]

$ sudo dnf -y reinstall gzip
[...]

$ sudo rpm -Va --noconfig | awk '$1 ~ /..5/ && $2 != "c"'
[no output])
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61564r1051229_chk'
  tag severity: 'medium'
  tag gid: 'V-257823'
  tag rid: 'SV-257823r1051231_rule'
  tag stig_id: 'RHEL-09-214030'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61488r1051230_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  misconfigured_files = command("rpm -Va --noconfig | awk '$1 ~ /..5/ && $2 != \"c\"'").stdout.strip.split("\n")

  describe 'All system file hashes' do
    it 'should match vendor hashes' do
      expect(misconfigured_files).to be_empty, "Misconfigured files:\n\t- #{misconfigured_files.join("\n\t- ")}"
    end
  end
end
