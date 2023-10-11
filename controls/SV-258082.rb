control 'SV-258082' do
  title 'RHEL 9 policycoreutils-python-utils package must be installed.'
  desc 'The policycoreutils-python-utils package is required to operate and manage an SELinux environment and its policies. It provides utilities such as semanage, audit2allow, audit2why, chcat, and sandbox.'
  desc 'check', 'Verify that RHEL 9 policycoreutils-python-utils service package is installed with the following command:

$ sudo dnf list --installed policycoreutils-python-utils

Example output:

policycoreutils-python-utils.noarch          3.3-6.el9_0

If the "policycoreutils-python-utils" package is not installed, this is a finding.'
  desc 'fix', 'Install the policycoreutils-python-utils service package (if the policycoreutils-python-utils service is not already installed) with the following command:

$ sudo dnf install policycoreutils-python-utils'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61823r926231_chk'
  tag severity: 'medium'
  tag gid: 'V-258082'
  tag rid: 'SV-258082r926233_rule'
  tag stig_id: 'RHEL-09-431030'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61747r926232_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
