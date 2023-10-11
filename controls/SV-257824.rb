control 'SV-257824' do
  title 'RHEL 9 must remove all software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by some adversaries.'
  desc 'check', 'Verify RHEL 9 removes all software components after updated versions have been installed with the following command:

$ grep clean /etc/dnf/dnf.conf 

clean_requirements_on_remove=1 

If "clean_requirements_on_remove" is not set to "1", this is a finding.'
  desc 'fix', 'Configure RHEL 9 to remove all software components after updated versions have been installed.

Edit the file /etc/dnf/dnf.conf by adding or editing the following line:

 clean_requirements_on_remove=1'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61565r925457_chk'
  tag severity: 'low'
  tag gid: 'V-257824'
  tag rid: 'SV-257824r925459_rule'
  tag stig_id: 'RHEL-09-214035'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag fix_id: 'F-61489r925458_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
