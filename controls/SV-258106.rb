control 'SV-258106' do
  title 'RHEL 9 must require users to provide a password for privilege escalation.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical that the user reauthenticate.

'
  desc 'check', 'Verify that "/etc/sudoers" has no occurrences of "NOPASSWD" with the following command:

$ sudo grep -ri nopasswd /etc/sudoers /etc/sudoers.d/*

If any occurrences of "NOPASSWD" are returned, this is a finding.'
  desc 'fix', %q(Configure RHEL 9 to not allow users to execute privileged actions without authenticating with a password.

Remove any occurrence of "NOPASSWD" found in "/etc/sudoers" file or files in the "/etc/sudoers.d" directory.

$ sudo sed -i '/NOPASSWD/ s/^/# /g' /etc/sudoers /etc/sudoers.d/*)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61847r926303_chk'
  tag severity: 'medium'
  tag gid: 'V-258106'
  tag rid: 'SV-258106r926305_rule'
  tag stig_id: 'RHEL-09-611085'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-61771r926304_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
