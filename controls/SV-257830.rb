control 'SV-257830' do
  title 'RHEL 9 must not install packages from the Extra Packages for Enterprise Linux (EPEL) repository.'
  desc 'The EPEL is a repository of high-quality open-source packages for enterprise-class Linux distributions such as RHEL, CentOS, AlmaLinux, Rocky Linux, and Oracle Linux. These packages are not part of the official distribution but are built using the same Fedora build system to ensure compatibility and maintain quality standards.'
  desc 'check', 'Verify that RHEL 9 is not able to install packages from the EPEL with the following command:

$ dnf repolist
rhel-9-for-x86_64-appstream-rpms                Red Hat Enterprise Linux 9 for x86_64 - AppStream (RPMs)
rhel-9-for-x86_64-baseos-rpms                   Red Hat Enterprise Linux 9 for x86_64 - BaseOS (RPMs)

If any repositories containing the word "epel" in the name exist, this is a finding.'
  desc 'fix', 'The repo package can be manually removed with the following command:

$ sudo dnf remove epel-release

Configure the operating system to disable use of the EPEL repository with the following command:

$ sudo dnf config-manager --set-disabled epel'
  impact 0.5
  tag check_id: 'C-61571r1134904_chk'
  tag severity: 'medium'
  tag gid: 'V-257830'
  tag rid: 'SV-257830r1134906_rule'
  tag stig_id: 'RHEL-09-215035'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-61495r1134905_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
