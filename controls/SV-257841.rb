control 'SV-257841' do
  title 'RHEL 9 must have the rng-tools package installed.'
  desc '"rng-tools" provides hardware random number generator tools, such as those used in the formation of x509/PKI certificates.'
  desc 'check', 'Verify that RHEL 9 has the rng-tools package installed with the following command:

$ sudo dnf list --installed rng-tools

Example output:

rng-tools.x86_64          6.14-2.git.b2b7934e.el9

If the "rng-tools" package is not installed, this is a finding.'
  desc 'fix', 'The rng-tools package can be installed with the following command:
 
$ sudo dnf install rng-tools'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61582r925508_chk'
  tag severity: 'medium'
  tag gid: 'V-257841'
  tag rid: 'SV-257841r925510_rule'
  tag stig_id: 'RHEL-09-215090'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61506r925509_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
