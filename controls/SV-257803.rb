control 'SV-257803' do
  title 'RHEL 9 must disable the kernel.core_pattern.'
  desc 'A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.'
  desc 'check', %q(Verify RHEL 9 disables storing core dumps with the following commands:

$ sysctl kernel.core_pattern

kernel.core_pattern = |/bin/false

If the returned line does not have a value of "|/bin/false", or a line is not returned and the need for core dumps is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.

Check that the configuration files are present to disable core dump storage.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F kernel.core_pattern | tail -1

kernel.core_pattern = |/bin/false

If "kernel.core_pattern" is not set to "|/bin/false" and is not documented with the ISSO as an operational requirement, or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to disable storing core dumps.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

kernel.core_pattern = |/bin/false

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61544r925394_chk'
  tag severity: 'medium'
  tag gid: 'V-257803'
  tag rid: 'SV-257803r925396_rule'
  tag stig_id: 'RHEL-09-213040'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61468r925395_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
