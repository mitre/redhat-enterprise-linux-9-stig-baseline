control 'SV-257986' do
  title 'RHEL 9 must enable the Pluggable Authentication Module (PAM) interface for SSHD.'
  desc 'When UsePAM is set to "yes", PAM runs through account and session types properly. This is important when restricted access to services based off of IP, time, or other factors of the account is needed. Additionally, this ensures users can inherit certain environment variables on login or disallow access to the server.'
  desc 'check', %q(Verify the RHEL 9 SSHD is configured to allow for the UsePAM interface with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*usepam'

UsePAM yes

If the "UsePAM" keyword is set to "no", is missing, or is commented out, this is a finding.)
  desc 'fix', 'Configure the RHEL 9 SSHD to use the UsePAM interface by adding or modifying the following line in "/etc/ssh/sshd_config" or in a file in "/etc/ssh/sshd_config.d".

UsePAM yes

Restart the SSH daemon for the settings to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61727r952182_chk'
  tag severity: 'high'
  tag gid: 'V-257986'
  tag rid: 'SV-257986r1045030_rule'
  tag stig_id: 'RHEL-09-255050'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-61651r1045029_fix'
  tag 'documentable'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  describe sshd_config do
    its('UsePAM') { should cmp 'yes' }
  end
end
