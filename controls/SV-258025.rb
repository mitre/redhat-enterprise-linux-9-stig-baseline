control 'SV-258025' do
  title 'RHEL 8 must initiate a session lock for graphical user interfaces when
the screensaver is activated.'
  desc "A session time-out lock is a temporary action taken when a user stops
work and moves away from the immediate physical vicinity of the information
system but does not log out because of the temporary nature of the absence.
Rather than relying on the user to manually lock their operating system session
prior to vacating the vicinity, operating systems need to be able to identify
when a user's session has idled and take action to initiate the session lock.

    The session lock is implemented at the point where session activity can be
determined and/or controlled."
  desc 'check', 'Verify the operating system initiates a session lock a for graphical user
interfaces when the screensaver is activated with the following command:

    Note: This requirement assumes the use of the RHEL 8 default graphical user
interface, Gnome Shell. If the system does not have any graphical user
interface installed, this requirement is Not Applicable.

    $ sudo gsettings get org.gnome.desktop.screensaver lock-delay

    uint32 5

    If the "uint32" setting is missing, or is not set to "5" or less, this
is a finding.'
  desc 'fix', 'Configure the operating system to initiate a session lock for graphical
user interfaces when a screensaver is activated.

    Create a database to contain the system-wide screensaver settings (if it
does not already exist) with the following command:

    Note: The example below is using the database "local" for the system, so
if the system is using another database in "/etc/dconf/profile/user", the
file should be created under the appropriate subdirectory.

    $ sudo touch /etc/dconf/db/local.d/00-screensaver

    [org/gnome/desktop/screensaver]
    lock-delay=uint32 5

    The "uint32" must be included along with the integer key values as shown.

    Update the system databases:

    $ sudo dconf update'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag satisfies: ['SRG-OS-000029-GPOS-00010', 'SRG-OS-000031-GPOS-00012', 'SRG-OS-000480-GPOS-00227']
  tag gid: 'V-244535'
  tag rid: 'SV-258025r743854_rule'
  tag stig_id: 'RHEL-08-020031'
  tag fix_id: 'F-47767r743853_fix'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
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
    describe command('gsettings get org.gnome.desktop.screensaver lock-delay') do
      its('stdout.strip') { should match(/uint32\s[0-5]/) }
    end
  end
end
