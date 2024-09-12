control 'SV-258140' do
  title 'RHEL 9 must have the rsyslog package installed.'
  desc 'rsyslogd is a system utility providing support for message logging. Support for both internet and Unix domain sockets enables this utility to support both local and remote logging. Couple this utility with "gnutls" (which is a secure communications library implementing the SSL, TLS, and DTLS protocols), to create a method to securely encrypt and offload auditing.'
  desc 'check', 'Verify that RHEL 9 has the rsyslogd package installed with the following command:

$ sudo dnf list --installed rsyslog

Example output:

rsyslog.x86_64          8.2102.0-101.el9_0.1

If the "rsyslogd" package is not installed, this is a finding.'
  desc 'fix', 'The rsyslogd package can be installed with the following command:

$ sudo dnf install rsyslogd'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag gid: 'V-258140'
  tag rid: 'SV-258140r959008_rule'
  tag stig_id: 'RHEL-09-652010'
  tag fix_id: 'F-61805r926406_fix'
  tag cci: ['CCI-000366', 'CCI-000154', 'CCI-001851']
  tag nist: ['CM-6 b', 'AU-6 (4)', 'AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('alternative_logging_method') == ''
    describe package('rsyslog') do
      it { should be_installed }
    end
  else
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  end
end
