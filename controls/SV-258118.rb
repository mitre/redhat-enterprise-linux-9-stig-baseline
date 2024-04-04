control 'SV-258118' do
  title 'The RHEL 8 operating system must not be configured to bypass password requirements for privilege escalation.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate.'
  desc 'check', 'Verify the operating system is not be configured to bypass password requirements for privilege escalation.

Check the configuration of the "/etc/pam.d/sudo" file with the following command:

$ sudo grep pam_succeed_if /etc/pam.d/sudo

If any occurrences of "pam_succeed_if" is returned from the command, this is a finding.'
  desc 'fix', 'Configure the operating system to require users to supply a password for privilege escalation.

Check the configuration of the "/etc/ pam.d/sudo" file with the following command:
$ sudo vi /etc/pam.d/sudo

Remove any occurrences of "pam_succeed_if" in the file.'
  impact 0.5
  tag check_id: 'C-55149r809358_chk'
  tag severity: 'medium'
  tag gid: 'V-251712'
  tag rid: 'SV-258118r854083_rule'
  tag stig_id: 'RHEL-08-010385'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-55103r854082_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
  tag 'host'
  tag 'container-conditional'

  if virtualization.system.eql?('docker') && !command('sudo').exist?
    impact 0.0
    describe 'Control not applicable within a container without sudo enabled' do
      skip 'Control not applicable within a container without sudo enabled'
    end
  else
    describe parse_config_file('/etc/pam.d/sudo') do
      its('content') { should_not match(/pam_succeed_if/) }
    end
  end
end
