control 'SV-257812' do
  title 'RHEL 8 must disable core dump backtraces.'
  desc 'It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    A core dump includes a memory image taken at the time the operating system
terminates an application. The memory image could contain sensitive data and is
generally useful only for developers trying to debug problems.'
  desc 'check', 'Verify the operating system disables core dump backtraces by issuing the
following command:

    $ sudo grep -i ProcessSizeMax /etc/systemd/coredump.conf

    ProcessSizeMax=0

    If the "ProcessSizeMax" item is missing, commented out, or the value is
anything other than "0" and the need for core dumps is not documented with
the Information System Security Officer (ISSO) as an operational requirement
for all domains that have the "core" item assigned, this is a finding.'
  desc 'fix', 'Configure the operating system to disable core dump backtraces.

Add or modify the following line in /etc/systemd/coredump.conf:

ProcessSizeMax=0'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230315'
  tag rid: 'SV-257812r627750_rule'
  tag stig_id: 'RHEL-08-010675'
  tag fix_id: 'F-32959r567692_fix'
  tag cci: ['CCI-000366']
  tag legacy: []
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe parse_config_file('/etc/systemd/coredump.conf') do
    its('Coredump.ProcessSizeMax') { should cmp '0' }
  end
end
