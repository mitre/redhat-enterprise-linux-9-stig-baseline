control 'SV-257812' do
  title 'RHEL 9 must disable core dump backtraces.'
  desc 'A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers or system operators trying to debug problems.

Enabling core dumps on production systems is not recommended; however, there may be overriding operational requirements to enable advanced debugging. Permitting temporary enablement of core dumps during such situations must be reviewed through local needs and policy.'
  desc 'check', 'Verify RHEL 9 disables core dump backtraces by issuing the following command:

$ grep -i process /etc/systemd/coredump.conf

ProcessSizeMax=0

If the "ProcessSizeMax" item is missing, commented out, or the value is anything other than "0" and the need for core dumps is not documented with the information system security officer (ISSO) as an operational requirement for all domains that have the "core" item assigned, this is a finding.'
  desc 'fix', 'Configure the operating system to disable core dump backtraces.

Add or modify the following line in /etc/systemd/coredump.conf:

ProcessSizeMax=0'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61553r925421_chk'
  tag severity: 'medium'
  tag gid: 'V-257812'
  tag rid: 'SV-257812r925423_rule'
  tag stig_id: 'RHEL-09-213085'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61477r925422_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
