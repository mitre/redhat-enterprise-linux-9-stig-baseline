control 'SV-257778' do
  title 'RHEL 9 vendor packaged system security patches and updates must be installed and up to date.'
  desc 'Installing software updates is a fundamental mitigation against the exploitation of publicly known vulnerabilities. If the most recent security patches and updates are not installed, unauthorized users may take advantage of weaknesses in the unpatched software. The lack of prompt attention to patching could result in a system compromise.'
  desc 'check', 'Verify RHEL 9 security patches and updates are installed and up to date. Updates are required to be applied with a frequency determined by organizational policy.

Obtain the list of available package security updates from Red Hat. The URL for updates is https://access.redhat.com/errata-search/. It is important to note that updates provided by Red Hat may not be present on the system if the underlying packages are not installed.

Check that the available package security updates have been installed on the system with the following command:

$ dnf history list | more

    ID | Command line | Date and time | Action(s) | Altered
-------------------------------------------------------------------------------
   70 | install aide | 2023-03-05 10:58 | Install | 1
   69 | update -y | 2023-03-04 14:34 | Update | 18 EE
   68 | install vlc | 2023-02-21 17:12 | Install | 21
   67 | update -y | 2023-02-21 17:04 | Update | 7 EE

Typical update frequency may be overridden by Information Assurance Vulnerability Alert (IAVA) notifications from CYBERCOM.

If the system is in noncompliance with the organizational patching policy, this is a finding.'
  desc 'fix', 'Install RHEL 9 security patches and updates at the organizationally defined frequency. If system updates are installed via a centralized repository that is configured on the system, all updates can be installed with the following command:

$ sudo dnf update'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257778'
  tag rid: 'SV-257778r925321_rule'
  tag stig_id: 'RHEL-09-211015'
  tag fix_id: 'F-61443r925320_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  only_if("This control takes a long time to execute so it has been disabled through 'slow_controls'") {
    !input('disable_slow_controls')
  }

  if input('disconnected_system')
    describe 'The system is set to a `disconnected` state and you must validate the state of the system packages manually' do
      skip 'The system is set to a `disconnected` state and you must validate the state of the system packages manually'
    end
  else
    updates = linux_update.updates
    package_names = updates.map { |h| h['name'] }

    describe.one do
      describe 'List of out-of-date packages' do
        subject { package_names }
        it { should be_empty }
      end
      updates.each do |update|
        describe package(update['name']) do
          its('version') { should eq update['version'] }
        end
      end
    end
  end
end
