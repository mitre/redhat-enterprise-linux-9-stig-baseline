control 'SV-258020' do
  title 'RHEL 9 must prevent a user from overriding the disabling of the graphical user smart card removal action.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, RHEL 9 needs to provide users with the ability to manually invoke a session lock so users can secure their session if it is necessary to temporarily vacate the immediate physical vicinity.

'
  desc 'check', %q(Verify RHEL 9 disables ability of the user to override the smart card removal action setting.

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Determine which profile the system database is using with the following command:

$ sudo grep system-db /etc/dconf/profile/user

system-db:local

Check that the removal action setting is locked from nonprivileged user modification with the following command:

Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.

$ grep 'removal-action' /etc/dconf/db/local.d/locks/*

/org/gnome/settings-daemon/peripherals/smartcard/removal-action

If the command does not return at least the example result, this is a finding.)
  desc 'fix', 'Add the following line to "/etc/dconf/db/local.d/locks/00-security-settings-lock" to prevent user override of the smart card removal action:

/org/gnome/settings-daemon/peripherals/smartcard/removal-action

Then update the dconf system databases:

$ sudo dconf update'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61761r926045_chk'
  tag severity: 'medium'
  tag gid: 'V-258020'
  tag rid: 'SV-258020r926047_rule'
  tag stig_id: 'RHEL-09-271050'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-61685r926046_fix'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag 'documentable'
  tag cci: ['CCI-000056', 'CCI-000058']
  tag nist: ['AC-11 b', 'AC-11 a']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  no_gui = command('ls /usr/share/xsessions/*').stderr.match?(/No such file or directory/)

  if no_gui
    impact 0.0
    describe 'The system does not have a GUI Desktop is installed, this control is Not Applicable' do
      skip 'A GUI desktop is not installed, this control is Not Applicable.'
    end
  else

    profile = command('grep system-db /etc/dconf/profile/user').stdout.strip.match(/:(\S+)$/)[1]

    describe command("grep ^removal-action /etc/dconf/db/#{profile}.d/locks/*") do
      its('stdout.strip') { should match(%r{^/org/gnome/settings-daemon/peripherals/smartcard/removal-action}) }
    end
  end
end
