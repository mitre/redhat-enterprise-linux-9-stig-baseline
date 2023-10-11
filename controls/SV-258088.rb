control 'SV-258088' do
  title 'RHEL 9 must restrict the use of the "su" command.'
  desc 'The "su" program allows to run commands with a substitute user and group ID. It is commonly used to run commands as the root user. Limiting access to such commands is considered a good security practice.

'
  desc 'check', 'Verify that RHEL 9 requires uses to be members of the "wheel" group with the following command:

$ grep pam_wheel /etc/pam.d/su 

auth             required        pam_wheel.so use_uid 

If a line for "pam_wheel.so" does not exist, or is commented out, this is a finding.'
  desc 'fix', %q(Configure RHEL 9 to require users to be in the "wheel" group to run "su" command.

In file "/etc/pam.d/su", uncomment the following line:

"#auth    required    pam_wheel.so use_uid"

$ sed '/^[[:space:]]*#[[:space:]]*auth[[:space:]]\+required[[:space:]]\+pam_wheel\.so[[:space:]]\+use_uid$/s/^[[:space:]]*#//' -i /etc/pam.d/su

If necessary, create a "wheel" group and add administrative users to the group.)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61829r926249_chk'
  tag severity: 'medium'
  tag gid: 'V-258088'
  tag rid: 'SV-258088r926251_rule'
  tag stig_id: 'RHEL-09-432035'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-61753r926250_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000312-GPOS-00123']
  tag 'documentable'
  tag cci: ['CCI-002038', 'CCI-002165']
  tag nist: ['IA-11', 'AC-3 (4)']
end
