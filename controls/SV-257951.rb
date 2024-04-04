control 'SV-257951' do
  title 'RHEL 8 must be configured to prevent unrestricted mail relaying.'
  desc 'If unrestricted mail relaying is permitted, unauthorized senders could
use this host as a mail relay for the purpose of sending spam or other
unauthorized activity.'
  desc 'check', 'Verify the system is configured to prevent unrestricted mail relaying.

    Determine if "postfix" is installed with the following commands:

    $ sudo yum list installed postfix

    postfix.x86_64  2:3.3.1-9.el8

    If postfix is not installed, this is Not Applicable.

    If postfix is installed, determine if it is configured to reject
connections from unknown or untrusted networks with the following command:

    $ sudo postconf -n smtpd_client_restrictions

    smtpd_client_restrictions = permit_mynetworks, reject

    If the "smtpd_client_restrictions" parameter contains any entries other
than "permit_mynetworks" and "reject", this is a finding.'
  desc 'fix', %q(If "postfix" is installed, modify the "/etc/postfix/main.cf" file to
restrict client connections to the local network with the following command:

    $ sudo postconf -e 'smtpd_client_restrictions = permit_mynetworks,reject')
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230550'
  tag rid: 'SV-257951r627750_rule'
  tag stig_id: 'RHEL-08-040290'
  tag fix_id: 'F-33194r568397_fix'
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
      skip 'The `postfix` package is not installed, this control is Not Applicable'
    end
  end
end
