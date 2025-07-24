control 'SV-257984' do
  title 'RHEL 9 SSHD must not allow blank passwords.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  desc 'check', %q(Verify that RHEL 9 remote access using SSH prevents logging on with a blank password with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*permitemptypasswords'

PermitEmptyPasswords no

If the "PermitEmptyPasswords" keyword is set to "yes", is missing, or is commented out, this is a finding.)
  desc 'fix', 'To configure the system to prevent SSH users from logging on with blank passwords edit the following line in "/etc/ssh/sshd_config" or in a file in "/etc/ssh/sshd_config.d":

PermitEmptyPasswords no

Restart the SSH daemon for the settings to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.7
  tag check_id: 'C-61725r1014847_chk'
  tag severity: 'high'
  tag gid: 'V-257984'
  tag rid: 'SV-257984r1045026_rule'
  tag stig_id: 'RHEL-09-255040'
  tag gtitle: 'SRG-OS-000106-GPOS-00053'
  tag fix_id: 'F-61649r1045025_fix'
  tag satisfies: ['SRG-OS-000106-GPOS-00053', 'SRG-OS-000480-GPOS-00229', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000766']
  tag nist: ['CM-6 b', 'IA-2 (2)']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  describe sshd_config do
    its('PermitEmptyPasswords') { should cmp 'no' }
  end
end
