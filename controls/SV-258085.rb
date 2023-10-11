control 'SV-258085' do
  title %q(RHEL 9 must use the invoking user's password for privilege escalation when using "sudo".)
  desc 'If the rootpw, targetpw, or runaspw flags are defined and not disabled, by default the operating system will prompt the invoking user for the "root" user password.'
  desc 'check', %q(Verify that the sudoers security policy is configured to use the invoking user's password for privilege escalation with the following command:

$ sudo egrep -i '(!rootpw|!targetpw|!runaspw)' /etc/sudoers /etc/sudoers.d/* | grep -v '#'

/etc/sudoers:Defaults !targetpw
/etc/sudoers:Defaults !rootpw
/etc/sudoers:Defaults !runaspw

If no results are returned, this is a finding.

If results are returned from more than one file location, this is a finding.

If "Defaults !targetpw" is not defined, this is a finding.

If "Defaults !rootpw" is not defined, this is a finding.

If "Defaults !runaspw" is not defined, this is a finding.)
  desc 'fix', 'Define the following in the Defaults section of the /etc/sudoers file or a single configuration file in the /etc/sudoers.d/ directory:

Defaults !targetpw
Defaults !rootpw
Defaults !runaspw'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61826r926240_chk'
  tag severity: 'medium'
  tag gid: 'V-258085'
  tag rid: 'SV-258085r926242_rule'
  tag stig_id: 'RHEL-09-432020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61750r926241_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
