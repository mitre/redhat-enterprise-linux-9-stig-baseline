control 'SV-258024' do
  title 'RHEL 9 must prevent a user from overriding the session idle-delay setting for the graphical user interface.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not logout because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, the GNOME desktop can be configured to identify when a user's session has idled and take action to initiate the session lock. As such, users should not be allowed to change session settings."
  desc 'check', 'Verify RHEL 9 prevents a user from overriding settings for graphical user interfaces.

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Determine which profile the system database is using with the following command:

$ sudo grep system-db /etc/dconf/profile/user

system-db:local

Check that graphical settings are locked from nonprivileged user modification with the following command:

Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.

$ sudo grep -i idle /etc/dconf/db/local.d/locks/*

/org/gnome/desktop/session/idle-delay

If the command does not return at least the example result, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to prevent a user from overriding settings for graphical user interfaces.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:

Note: The example below is using the database "local" for the system, so if the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

$ sudo touch /etc/dconf/db/local.d/locks/session

Add the following setting to prevent nonprivileged users from modifying it:

/org/gnome/desktop/session/idle-delay'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag satisfies: ['SRG-OS-000029-GPOS-00010', 'SRG-OS-000031-GPOS-00012', 'SRG-OS-000480-GPOS-00227']
  tag gid: 'V-258024'
  tag rid: 'SV-258024r958402_rule'
  tag stig_id: 'RHEL-09-271070'
  tag fix_id: 'F-61689r926058_fix'
  tag cci: ['CCI-000057', 'CCI-000060']
  tag nist: ['AC-11 a', 'AC-11 (1)']
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
    describe command('grep -i idle /etc/dconf/db/local.d/locks/*') do
      it 'checks if idle delay is set' do
        expect(subject.stdout.split).to include('/org/gnome/desktop/session/idle-delay'), 'The idle delay is not set. Please ensure it is set.'
      end
    end
  end
end
