control 'SV-258027' do
  title 'RHEL 9 must conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  desc 'Setting the screensaver mode to blank-only conceals the contents of the display from passersby.'
  desc 'check', %q(To ensure the screensaver is configured to be blank, run the following command:

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ gsettings get org.gnome.desktop.screensaver picture-uri

If properly configured, the output should be "''".

To ensure that users cannot set the screensaver background, run the following:

$ grep picture-uri /etc/dconf/db/local.d/locks/*

If properly configured, the output should be "/org/gnome/desktop/screensaver/picture-uri".

If it is not set or configured properly, this is a finding.)
  desc 'fix', %q(The dconf settings can be edited in the /etc/dconf/db/* location.

First, add or update the [org/gnome/desktop/screensaver] section of the "/etc/dconf/db/local.d/00-security-settings" database file and add or update the following lines:

[org/gnome/desktop/screensaver]
picture-uri=''

Then, add the following line to "/etc/dconf/db/local.d/locks/00-security-settings-lock" to prevent user modification:

/org/gnome/desktop/screensaver/picture-uri

Finally, update the dconf system databases:

$ sudo dconf update)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61768r926066_chk'
  tag severity: 'medium'
  tag gid: 'V-258027'
  tag rid: 'SV-258027r926068_rule'
  tag stig_id: 'RHEL-09-271085'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-61692r926067_fix'
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
