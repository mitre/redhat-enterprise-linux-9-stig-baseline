control 'SV-272496' do
  title 'RHEL 9 must elevate the SELinux context when an administrator calls the sudo command.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.

Preventing nonprivileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Nonprivileged users are individuals who do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from nonprivileged users.'
  desc 'check', 'Verify that RHEL 9 elevates the SELinux context when an administrator calls the sudo command with the following command:

This command must be run as root:

# grep -r sysadm_r /etc/sudoers /etc/sudoers.d
%{designated_group_or_user_name} ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL

If conflicting results are returned, this is a finding.

If a designated sudoers administrator group or account(s) is not configured to elevate the SELinux type and role to "sysadm_t" and "sysadm_r" with the use of the sudo command, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to elevate the SELinux context when an administrator calls the sudo command.

Edit a file in the "/etc/sudoers.d" directory with the following command:

$ sudo visudo -f /etc/sudoers.d/<customfile>

Use the following example to build the <customfile> in the /etc/sudoers.d directory to allow any administrator belonging to a designated sudoers admin group to elevate their SELinux context with the use of the sudo command:

%{designated_group_or_user_name} ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL

Remove any configurations that conflict with the above from the following locations:
 
/etc/sudoers
/etc/sudoers.d/'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-76549r1069439_chk'
  tag severity: 'medium'
  tag gid: 'V-272496'
  tag rid: 'SV-272496r1082184_rule'
  tag stig_id: 'RHEL-09-431016'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-76453r1082183_fix'
  tag 'documentable'
  tag legacy: ['SV-70979', 'V-56719']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

  only_if('Control not applicable within a container without sudo enabled', impact: 0.0) do
    !virtualization.system.eql?('docker')
  end

  output = command('grep -r sysadm_r /etc/sudoers /etc/sudoers.d').stdout.strip

  describe 'The sudoers SELinux context rule' do
    it 'should match the expected SELinux role and type for privileged access' do
      expect(output).to match(/^\s*%[\w-]+\s+ALL=\(ALL\)\s+TYPE=sysadm_t\s+ROLE=sysadm_r\s+ALL/), 'No matching sudoers rule found that elevates to sysadm_t/sysadm_r'
    end
  end
end
