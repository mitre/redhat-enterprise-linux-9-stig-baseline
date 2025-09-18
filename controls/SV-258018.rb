control 'SV-258018' do
  title 'RHEL 9 must not allow unattended or automatic logon via the graphical user interface.'
  desc 'Failure to restrict system access to authenticated users negatively
impacts operating system security.'
  desc 'check', 'Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify RHEL 9 does not allow an unattended or automatic logon to the system via a graphical user interface.

Check for the value of the "AutomaticLoginEnable" in the "/etc/gdm/custom.conf" file with the following command:

$  grep -i automaticlogin /etc/gdm/custom.conf

AutomaticLoginEnable=false

If the value of "AutomaticLoginEnable" is not set to "false", this is a finding.'
  desc 'fix', 'Configure the GNOME desktop display manager to disable automatic login.

Set AutomaticLoginEnable to false in the [daemon] section in /etc/gdm/custom.conf. For example:

[daemon]
AutomaticLoginEnable=false'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag gid: 'V-258018'
  tag rid: 'SV-258018r1045090_rule'
  tag stig_id: 'RHEL-09-271040'
  tag fix_id: 'F-61683r926040_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This requirement is Not Applicable inside a container') {
    !virtualization.system.eql?('docker')
  }

  g = guis(input('possibly_installed_guis'))

  if g.has_gui?
    conf_path = '/etc/gdm/custom.conf'
    conf_file = file(conf_path)
    conf = parse_config_file(conf_path)

    if g.has_non_gnome_gui?
      if g.has_gnome_gui?
        if !conf_file.exist?
          describe conf_file do
            it { should exist }
          end
        elsif conf.params['daemon']['AutomaticLoginEnable'] == 'false'
          describe "`gdm` config file at #{conf_path}" do
            subject { conf }
            it 'should have `AutomaticLoginEnable` set to `false` in the `[daemon]` section.' do
              expect(subject.params['daemon']['AutomaticLoginEnable']).to eq('false')
            end
          end
        end
      end

      describe 'Non-GNOME desktop environments detected' do
        skip "Manual check required as there is no guidance for non-GNOME desktop environments, which were identified as being installed on the system.  Investigate the following, possibly related packages to determine which desktop environments are installed and then determine a method to ensure that each of those desktop environments' configuration is up-to-date and matches policy:\n\t- #{g.installed_non_gnome_guis.join("\n\t- ")}"
      end
    elsif conf_file.exist?
      describe "`gdm` config file at #{conf_path}" do
        subject { conf }
        it 'should have `AutomaticLoginEnable` set to `false` in the `[daemon]` section.' do
          expect(subject.params['daemon']['AutomaticLoginEnable']).to eq('false')
        end
      end
    else
      describe conf_file do
        it { should exist }
      end
    end
  else
    impact 0.0
    describe 'The system does not have a GUI/desktop environment installed; this control is Not Applicable' do
      skip 'A GUI/desktop environment is not installed; this control is Not Applicable.'
    end
  end
end
