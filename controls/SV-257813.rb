control 'SV-257813' do
  title 'RHEL 9 must disable storing core dumps.'
  desc 'A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers or system operators trying to debug problems. Enabling core dumps on production systems is not recommended; however, there may be overriding operational requirements to enable advanced debugging. Permitting temporary enablement of core dumps during such situations must be reviewed through local needs and policy.'
  desc 'check', 'Verify RHEL 9 disables storing core dumps for all users by issuing the following command:

$ grep -i storage /etc/systemd/coredump.conf

Storage=none

If the "Storage" item is missing, commented out, or the value is anything other than "none" and the need for core dumps is not documented with the information system security officer (ISSO) as an operational requirement for all domains that have the "core" item assigned, this is a finding.'
  desc 'fix', 'Configure the operating system to disable storing core dumps for all users.

Add or modify the following line in /etc/systemd/coredump.conf:

Storage=none'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61554r925424_chk'
  tag severity: 'medium'
  tag gid: 'V-257813'
  tag rid: 'SV-257813r925426_rule'
  tag stig_id: 'RHEL-09-213090'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61478r925425_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
