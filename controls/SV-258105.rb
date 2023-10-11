control 'SV-258105' do
  title 'RHEL 9 passwords must have a 24 hours minimum password lifetime restriction in /etc/shadow.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', %q(Verify that RHEL 9 has configured the minimum time period between password changes for each user account as one day or greater with the following command:

$ sudo awk -F: '$4 < 1 {print $1 " " $4}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.)
  desc 'fix', 'Configure noncompliant accounts to enforce a 24 hour minimum password lifetime:

$ sudo passwd -n 1 [user]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61846r926300_chk'
  tag severity: 'medium'
  tag gid: 'V-258105'
  tag rid: 'SV-258105r926302_rule'
  tag stig_id: 'RHEL-09-611080'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-61770r926301_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
