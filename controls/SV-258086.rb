control 'SV-258086' do
  title 'RHEL 9 must require users to reauthenticate for privilege escalation.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical that the user reauthenticate.

'
  desc 'check', %q(Verify that "/etc/sudoers" has no occurrences of "!authenticate" with the following command:

$ sudo grep -i '!authenticate' /etc/sudoers /etc/sudoers.d/*

If any occurrences of "!authenticate" are returned, this is a finding.)
  desc 'fix', %q(Configure RHEL 9 to not allow users to execute privileged actions without authenticating.

Remove any occurrence of "!authenticate" found in "/etc/sudoers" file or files in the "/etc/sudoers.d" directory.

$ sudo sed -i '/\!authenticate/ s/^/# /g' /etc/sudoers /etc/sudoers.d/*)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61827r926243_chk'
  tag severity: 'medium'
  tag gid: 'V-258086'
  tag rid: 'SV-258086r926245_rule'
  tag stig_id: 'RHEL-09-432025'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-61751r926244_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
