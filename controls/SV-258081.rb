control 'SV-258081' do
  title 'RHEL 9 must have policycoreutils package installed.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Policycoreutils contains the policy core utilities that are required for basic operation of an SELinux-enabled system. These utilities include load_policy to load SELinux policies, setfile to label filesystems, newrole to switch roles, and run_init to run /etc/init.d scripts in the proper context.

'
  desc 'check', 'Verify RHEL 9 has the policycoreutils package installed with the following command:

$ sudo dnf list --installed policycoreutils

Example output:

policycoreutils.x86_64          3.3-6.el9_0                                                 

If the "policycoreutils" package is not installed, this is a finding.'
  desc 'fix', 'The policycoreutils package can be installed with the following command:
 
$ sudo dnf install policycoreutils'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61822r926228_chk'
  tag severity: 'medium'
  tag gid: 'V-258081'
  tag rid: 'SV-258081r926230_rule'
  tag stig_id: 'RHEL-09-431025'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61746r926229_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00227', 'SRG-OS-000134-GPOS-00068']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001084']
  tag nist: ['CM-6 b', 'SC-3']
end
