control 'SV-258141' do
  title 'RHEL 9 must have the packages required for encrypting offloaded audit logs installed.'
  desc 'The rsyslog-gnutls package provides Transport Layer Security (TLS) support for the rsyslog daemon, which enables secure remote logging.

'
  desc 'check', 'Verify that RHEL 9 has the rsyslog-gnutls package installed with the following command:

$ sudo dnf list --installed rsyslog-gnutls

Example output:

rsyslog-gnutls.x86_64          8.2102.0-101.el9_0.1

If the "rsyslog-gnutls" package is not installed, this is a finding.'
  desc 'fix', 'The  rsyslog-gnutls package can be installed with the following command:
 
$ sudo dnf install rsyslog-gnutls'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61882r926408_chk'
  tag severity: 'medium'
  tag gid: 'V-258141'
  tag rid: 'SV-258141r926410_rule'
  tag stig_id: 'RHEL-09-652015'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61806r926409_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00227', 'SRG-OS-000120-GPOS-00061']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000803']
  tag nist: ['CM-6 b', 'IA-7']
end
