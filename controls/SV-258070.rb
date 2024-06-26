control 'SV-258070' do
  title 'RHEL 9 must log username information when unsuccessful logon attempts occur.'
  desc 'Without auditing of these events, it may be harder or impossible to identify what an attacker did after an attack.'
  desc 'check', 'Verify the "/etc/security/faillock.conf" file is configured to log username information when unsuccessful logon attempts occur with the following command:

$ grep audit /etc/security/faillock.conf

audit

If the "audit" option is not set, is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to log username information when unsuccessful logon attempts occur.

Add/modify the "/etc/security/faillock.conf" file to match the following line:

audit'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'V-258070'
  tag rid: 'SV-258070r926197_rule'
  tag stig_id: 'RHEL-09-412045'
  tag fix_id: 'F-61735r926196_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
  tag 'host'
  tag 'container'

  describe parse_config_file('/etc/security/faillock.conf') do
    its('audit') { should_not be_nil }
  end
end
