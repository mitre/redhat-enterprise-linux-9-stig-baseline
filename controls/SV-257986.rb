control 'SV-257986' do
  title 'RHEL 9 must enable the Pluggable Authentication Module (PAM) interface for SSHD.'
  desc 'When UsePAM is set to "yes", PAM runs through account and session types properly. This is important when restricted access to services based off of IP, time, or other factors of the account is needed. Additionally, this ensures users can inherit certain environment variables on login or disallow access to the server.'
  desc 'check', 'Verify the RHEL 9 SSHD is configured to allow for the UsePAM interface with the following command:

$ sudo grep -i usepam /etc/ssh/sshd_config

UsePAM yes

If the "UsePAM" keyword is set to "no", is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure the RHEL 9 SSHD to use the UsePAM interface add or modify the following line in "/etc/ssh/sshd_config".

UsePAM yes

Restart the SSH daemon for the settings to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61727r925943_chk'
  tag severity: 'high'
  tag gid: 'V-257986'
  tag rid: 'SV-257986r925945_rule'
  tag stig_id: 'RHEL-09-255050'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-61651r925944_fix'
  tag 'documentable'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
