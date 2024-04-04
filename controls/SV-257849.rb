control 'SV-257849' do
  title 'The RHEL 8 file system automounter must be disabled unless required.'
  desc 'Automatically mounting file systems permits easy introduction of
unknown devices, thereby facilitating malicious activity.'
  desc 'check', 'Verify the operating system disables the ability to automount devices.

    Check to see if automounter service is active with the following command:

    Note: If the autofs service is not installed, this requirement is not
applicable.

    $ sudo systemctl status autofs

    autofs.service - Automounts filesystems on demand
    Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled)
    Active: inactive (dead)

    If the "autofs" status is set to "active" and is not documented with
the Information System Security Officer (ISSO) as an operational requirement,
this is a finding.'
  desc 'fix', 'Configure the operating system to disable the ability to automount devices.

    Turn off the automount service with the following commands:

    $ sudo systemctl stop autofs
    $ sudo systemctl disable autofs

    If "autofs" is required for Network File System (NFS), it must be
documented with the ISSO.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag gid: 'V-230502'
  tag rid: 'SV-257849r627750_rule'
  tag stig_id: 'RHEL-08-040070'
  tag fix_id: 'F-33146r568253_fix'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('autofs_required') == true
    describe systemd_service('autofs.service') do
      it { should be_running }
      it { should be_enabled }
      it { should be_installed }
    end
  elsif package('autofs').installed?
    describe systemd_service('autofs.service') do
      it { should_not be_running }
      it { should_not be_enabled }
      it { should_not be_installed }
    end
  else
    impact 0.0
    describe 'The autofs service is not installed' do
      skip 'The autofs service is not installed, this control is Not Applicable.'
    end
  end
end
