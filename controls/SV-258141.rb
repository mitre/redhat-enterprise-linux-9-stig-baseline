control 'SV-258141' do
  title 'RHEL 9 must have the packages required for encrypting offloaded audit logs installed.'
  desc 'The rsyslog-gnutls package provides Transport Layer Security (TLS) support for the rsyslog daemon, which enables secure remote logging.'
  desc 'check', 'Verify that RHEL 9 has the rsyslog-gnutls package installed with the following command:

$ dnf list --installed rsyslog-gnutls

Example output:

rsyslog-gnutls.x86_64          8.2102.0-101.el9_0.1

If the "rsyslog-gnutls" package is not installed, this is a finding.'
  desc 'fix', 'The  rsyslog-gnutls package can be installed with the following command:

$ sudo dnf install rsyslog-gnutls'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-258141'
  tag rid: 'SV-258141r1045280_rule'
  tag stig_id: 'RHEL-09-652015'
  tag fix_id: 'F-61806r926409_fix'
  tag cci: ['CCI-000366', 'CCI-000803']
  tag nist: ['CM-6 b', 'IA-7']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('alternative_logging_method') != ''
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  else
    describe package('rsyslog-gnutls') do
      it { should be_installed }
    end
  end
end
