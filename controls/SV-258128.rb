control 'SV-258128' do
  title 'RHEL 9 must require authentication to access emergency mode.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DOD-approved PKIs, all DOD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

This requirement prevents attackers with physical access from trivially bypassing security on the machine and gaining root access. Such accesses are further prevented by configuring the bootloader password.'
  desc 'check', 'Verify RHEL 9 requires authentication for emergency mode with the following command:

$ grep sulogin /usr/lib/systemd/system/emergency.service

ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency

If the line is not returned from the default systemd file, use the following command to look for modifications to the emergency.service:

$ grep sulogin /etc/systemd/system/emergency.service.d/*.conf

If the line is not returned from either location this is a finding.

Note: The configuration setting can only be in either the default location, or in the drop in file, not both locations.'
  desc 'fix', 'Configure RHEL 9 to require authentication for emergency mode.

Create a directory for supplementary configuration files:
$ sudo mkdir /etc/systemd/system/emergency.service.d/

Copy the original file emergency.service file to the new directory with:
$ sudo cp  /usr/lib/systemd/system/emergency.service  /etc/systemd/system/emergency.service.d/emergency.service.conf

Open the new file:
$ sudo vi /etc/systemd/system/emergency.service.d/emergency.service.conf

Add or modify the following line in the new file:
ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency

Comment out or remove the ExecStart and ExecStartPre lines in /usr/lib/systemd/system/emergency.service as they can only exist in one location.

Apply changes to unit files without rebooting the system:
$ sudo systemctl daemon-reload'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag gid: 'V-258128'
  tag rid: 'SV-258128r1155626_rule'
  tag stig_id: 'RHEL-09-611195'
  tag fix_id: 'F-61793r1155625_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) && command('systemd-detect-virt --container').exit_status != 0
  }

  describe service('emergency') do
    its('params.ExecStart') { should include '/usr/lib/systemd/systemd-sulogin-shell emergency' }
  end
end
