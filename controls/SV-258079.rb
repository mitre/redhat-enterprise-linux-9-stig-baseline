control 'SV-258079' do
  title 'RHEL 9 must enable the SELinux targeted policy.'
  desc 'Setting the SELinux policy to "targeted" or a more specialized policy ensures the system will confine processes that are likely to be targeted for exploitation, such as network or system services.

Note: During the development or debugging of SELinux modules, it is common to temporarily place nonproduction systems in "permissive" mode. In such temporary cases, SELinux policies should be developed, and once work is completed, the system should be reconfigured to "targeted".'
  desc 'check', 'Verify the SELINUX on RHEL 9 is using the targeted policy with the following command:

$ sestatus | grep policy

Loaded policy name:             targeted

If the loaded policy name is not "targeted", this is a finding.'
  desc 'fix', 'Configure RHEL 9 to use the targetd SELINUX policy.

Edit the file "/etc/selinux/config" and add or modify the following line:

 SELINUXTYPE=targeted 

A reboot is required for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61820r926222_chk'
  tag severity: 'medium'
  tag gid: 'V-258079'
  tag rid: 'SV-258079r926224_rule'
  tag stig_id: 'RHEL-09-431015'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-61744r926223_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
