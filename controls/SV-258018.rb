control 'SV-258018' do
  title 'RHEL 9 must not allow unattended or automatic logon via the graphical user interface.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'Verify RHEL 9 does not allow an unattended or automatic logon to the system via a graphical user interface.

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Check for the value of the "AutomaticLoginEnable" in the "/etc/gdm/custom.conf" file with the following command:

$  grep -i automaticlogin /etc/gdm/custom.conf

[daemon]
AutomaticLoginEnable=false

If the value of "AutomaticLoginEnable" is not set to "false", this is a finding.'
  desc 'fix', 'Configure the GNOME desktop display manager to disable automatic login.

Set AutomaticLoginEnable to false in the [daemon] section in /etc/gdm/custom.conf. For example:

[daemon]
AutomaticLoginEnable=false'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61759r926039_chk'
  tag severity: 'high'
  tag gid: 'V-258018'
  tag rid: 'SV-258018r926041_rule'
  tag stig_id: 'RHEL-09-271040'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-61683r926040_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
