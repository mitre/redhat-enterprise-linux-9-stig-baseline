control 'SV-257951' do
  title 'RHEL 9 must be configured to prevent unrestricted mail relaying.'
  desc 'If unrestricted mail relaying is permitted, unauthorized senders could
use this host as a mail relay for the purpose of sending spam or other
unauthorized activity.'
  desc 'check', 'If postfix is not installed, this is Not Applicable.

Verify RHEL 9 is configured to prevent unrestricted mail relaying with the following command:

$ postconf -n smtpd_client_restrictions

smtpd_client_restrictions = permit_mynetworks,reject

If the "smtpd_client_restrictions" parameter contains any entries other than "permit_mynetworks" and "reject", and the additional entries have not been documented with the information system security officer (ISSO), this is a finding.'
  desc 'fix', "Modify the postfix configuration file to restrict client connections to the local network with the following command:

$ sudo postconf -e 'smtpd_client_restrictions = permit_mynetworks,reject'"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257951'
  tag rid: 'SV-257951r1014843_rule'
  tag stig_id: 'RHEL-09-252050'
  tag fix_id: 'F-61616r925839_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  if package('postfix').installed?
    describe command('postconf -n smtpd_client_restrictions') do
      its('stdout.strip') {
        should match(/^smtpd_client_restrictions\s+=\s+(permit_mynetworks|reject)($|(,\s*(permit_mynetworks|reject)\s*$))/i)
      }
    end
  else
    impact 0.0
    describe 'The `postfix` package is not installed' do
      skip 'The `postfix` package is not installed; this control is Not Applicable'
    end
  end
end
