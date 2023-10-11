control 'SV-258118' do
  title 'RHEL 9 must not be configured to bypass password requirements for privilege escalation.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization. When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.

'
  desc 'check', 'Verify the operating system is not configured to bypass password requirements for privilege escalation with the following command:

$ sudo grep pam_succeed_if /etc/pam.d/sudo 

If any occurrences of "pam_succeed_if" are returned, this is a finding.'
  desc 'fix', 'Configure the operating system to require users to supply a password for privilege escalation.

Remove any occurrences of " pam_succeed_if " in the  "/etc/pam.d/sudo" file.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61859r926339_chk'
  tag severity: 'medium'
  tag gid: 'V-258118'
  tag rid: 'SV-258118r926341_rule'
  tag stig_id: 'RHEL-09-611145'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-61783r926340_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
