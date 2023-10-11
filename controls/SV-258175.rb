control 'SV-258175' do
  title 'RHEL 9 audispd-plugins package must be installed.'
  desc '"audispd-plugins" provides plugins for the real-time interface to the audit subsystem, "audispd". These plugins can do things like relay events to remote machines or analyze events for suspicious behavior.'
  desc 'check', 'Verify that RHEL 9 has the audispd-plugins package for installed with the following command:

$ sudo dnf list --installed audispd-plugins

Example output:

audispd-plugins.x86_64          3.0.7-101.el9_0.2

If the "audispd-plugins" package is not installed, this is a finding.'
  desc 'fix', 'The audispd-plugins package can be installed with the following command:
 
$ sudo dnf install audispd-plugins'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61916r926510_chk'
  tag severity: 'medium'
  tag gid: 'V-258175'
  tag rid: 'SV-258175r926512_rule'
  tag stig_id: 'RHEL-09-653130'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-61840r926511_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
