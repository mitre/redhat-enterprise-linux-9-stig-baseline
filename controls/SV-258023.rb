control 'SV-258023' do
  title 'RHEL 8 must automatically lock graphical user sessions after 15
minutes of inactivity.'
  desc 'A session lock is a temporary action taken when a user stops work and
moves away from the immediate physical vicinity of the information system but
does not want to log out because of the temporary nature of the absence.

    The session lock is implemented at the point where session activity can be
determined. Rather than be forced to wait for a period of time to expire before
the user session can be locked, RHEL 8 needs to provide users with the ability
to manually invoke a session lock so users can secure their session if it is
necessary to temporarily vacate the immediate physical vicinity.'
  desc 'check', 'Verify the operating system initiates a session lock after a 15-minute
period of inactivity for graphical user interfaces with the following commands:

    This requirement assumes the use of the RHEL 8 default graphical user
interface, Gnome Shell. If the system does not have any graphical user
interface installed, this requirement is Not Applicable.

    $ sudo gsettings get org.gnome.desktop.session idle-delay

    uint32 900

    If "idle-delay" is set to "0" or a value greater than "900", this is
a finding.'
  desc 'fix', 'Configure the operating system to initiate a screensaver after a 15-minute
period of inactivity for graphical user interfaces.

    Create a database to contain the system-wide screensaver settings (if it
does not already exist) with the following command:

    $ sudo touch /etc/dconf/db/local.d/00-screensaver

    Edit /etc/dconf/db/local.d/00-screensaver and add or update the following
lines:

    [org/gnome/desktop/session]
    # Set the lock time out to 900 seconds before the session is considered idle
    idle-delay=uint32 900

    Update the system databases:

    $ sudo dconf update'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag satisfies: ['SRG-OS-000029-GPOS-00010', 'SRG-OS-000031-GPOS-00012']
  tag gid: 'V-230352'
  tag rid: 'SV-258023r646876_rule'
  tag stig_id: 'RHEL-08-020060'
  tag fix_id: 'F-32996r567803_fix'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if package('gnome-desktop3').installed?
    describe command("gsettings get org.gnome.desktop.session idle-delay | cut -d ' ' -f2") do
      its('stdout.strip') { should cmp <= input('system_inactivity_timeout') }
    end
  else
    impact 0.0
    describe 'The system does not have GNOME installed' do
      skip "The system does not have GNOME installed, this requirement is Not
        Applicable."
    end
  end
end
