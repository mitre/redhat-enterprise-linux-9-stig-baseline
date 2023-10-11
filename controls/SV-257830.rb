control 'SV-257830' do
  title 'RHEL 9 must not have the rsh-server package installed.'
  desc 'The "rsh-server" service provides unencrypted remote access service, which does not provide for the confidentiality and integrity of user passwords or the remote session and has very weak authentication. If a privileged user were to login using this service, the privileged user password could be compromised. The "rsh-server" package provides several obsolete and insecure network services. Removing it decreases the risk of accidental (or intentional) activation of those services.'
  desc 'check', 'Verify that the rsh-server package is not installed with the following command:

$ sudo dnf list --installed rsh-server

Error: No matching Packages to list

If the "rsh-server" package is installed, this is a finding.'
  desc 'fix', 'Remove the rsh-server package with the following command:

$ sudo dnf remove rsh-server'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61571r925475_chk'
  tag severity: 'medium'
  tag gid: 'V-257830'
  tag rid: 'SV-257830r925477_rule'
  tag stig_id: 'RHEL-09-215035'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-61495r925476_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
