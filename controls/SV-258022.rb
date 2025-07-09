control 'SV-258022' do
  title 'RHEL 9 must prevent a user from overriding the screensaver lock-enabled setting for the graphical user interface.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled.

Implementing session settings will have little value if a user is able to manipulate these settings from the defaults prescribed in the other requirements of this implementation guide."
  desc 'check', 'Note: This requirement assumes the use of the RHEL 9 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify RHEL 9 prevents a user from overriding settings for graphical user interfaces. 

$ gsettings writable org.gnome.desktop.screensaver lock-enabled
 
false
 
If "lock-enabled" is writable and the result is "true", this is a finding.'
  desc 'fix', 'Configure RHEL 9 to prevent a user from overriding settings for graphical user interfaces.

Create a database to contain the systemwide screensaver settings (if it does not already exist) with the following command: 

Note: The example below is using the database "local" for the system. If the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

$ sudo touch /etc/dconf/db/local.d/locks/session

Add the following setting to prevent nonprivileged users from modifying it:

/org/gnome/desktop/screensaver/lock-enabled

Run the following command to update the database:

$ sudo dconf update'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag satisfies: ['SRG-OS-000029-GPOS-00010', 'SRG-OS-000031-GPOS-00012', 'SRG-OS-000480-GPOS-00227', 'SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag gid: 'V-258022'
  tag rid: 'SV-258022r1045097_rule'
  tag stig_id: 'RHEL-09-271060'
  tag fix_id: 'F-61687r1045096_fix'
  tag cci: ['CCI-000057', 'CCI-000056', 'CCI-000058']
  tag nist: ['AC-11 a', 'AC-11 b']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if package('gnome-desktop3').installed?
    describe command('grep -i lock-enabled /etc/dconf/db/local.d/locks/*') do
      its('stdout.strip') { should match %r(/org/gnome/desktop/screensaver/lock-enabled) }
    end
  else
    impact 0.0
    describe 'The GNOME desktop is not installed, this control is Not Applicable.' do
      skip 'The GNOME desktop is not installed, this control is Not Applicable.'
    end
  end
end
