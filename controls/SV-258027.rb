control 'SV-258027' do
  title 'RHEL 9 must conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  desc 'Setting the screensaver mode to blank-only conceals the contents of the display from passersby.'
  desc 'check', 'Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

To ensure the screensaver is configured to be blank, run the following command:

$ gsettings writable org.gnome.desktop.screensaver picture-uri
 
false
 
If "picture-uri" is writable and the result is "true", this is a finding.'
  desc 'fix', %q(Configure RHEL 9 to prevent a user from overriding the picture-uri setting for graphical user interfaces.

In the file "/etc/dconf/db/local.d/00-security-settings", add or update the following lines:

[org/gnome/desktop/screensaver]
picture-uri=''

Prevent user modification by adding the following line to "/etc/dconf/db/local.d/locks/00-security-settings-lock":

/org/gnome/desktop/screensaver/picture-uri

Update the dconf system databases:

$ sudo dconf update)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61768r1045104_chk'
  tag severity: 'medium'
  tag gid: 'V-258027'
  tag rid: 'SV-258027r1045106_rule'
  tag stig_id: 'RHEL-09-271085'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-61692r1045105_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
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

    describe command("grep ^picture-uri /etc/dconf/db/#{profile}.d/locks/*") do
      its('stdout.strip') { should match(%r{^/org/gnome/desktop/screensaver/picture-uri}) }
    end
  end
end
