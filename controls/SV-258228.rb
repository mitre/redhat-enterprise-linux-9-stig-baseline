control 'SV-258228' do
  title 'RHEL 9 audit system must protect logon UIDs from unauthorized change.'
  desc 'If modification of login user identifiers (UIDs) is not prevented, they can be changed by nonprivileged users and make auditing complicated or impossible.

'
  desc 'check', 'Verify the audit system prevents unauthorized changes to logon UIDs with the following command:

$ sudo grep -i immutable /etc/audit/audit.rules

--loginuid-immutable

If the "--loginuid-immutable" option is not returned in the "/etc/audit/audit.rules", or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 auditing to prevent modification of login UIDs once they are set by adding the following line to /etc/audit/rules.d/audit.rules:

--loginuid-immutable

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61969r926669_chk'
  tag severity: 'medium'
  tag gid: 'V-258228'
  tag rid: 'SV-258228r926671_rule'
  tag stig_id: 'RHEL-09-654270'
  tag gtitle: 'SRG-OS-000462-GPOS-00206'
  tag fix_id: 'F-61893r926670_fix'
  tag satisfies: ['SRG-OS-000462-GPOS-00206', 'SRG-OS-000475-GPOS-00220', 'SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-000172']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-12 c']
end
