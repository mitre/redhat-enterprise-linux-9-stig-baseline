control 'SV-257778' do
  title 'RHEL 8 vendor packaged system security patches and updates must be installed and up to date.'
  desc 'Timely patching is critical for maintaining the operational
    availability, confidentiality, and integrity of information technology (IT)
    systems. However, failure to keep operating system and application software
    patched is a common mistake made by IT professionals. New patches are released
    daily, and it is often difficult for even experienced System Administrators to
    keep abreast of all the new patches. When new weaknesses in an operating system
    exist, patches are usually made available by the vendor to resolve the
    problems. If the most recent security patches and updates are not installed,
    unauthorized users may take advantage of weaknesses in the unpatched software.
    The lack of prompt attention to patching could result in a system compromise.'
  desc 'check', 'Verify the operating system security patches and updates are installed and
    up to date. Updates are required to be applied with a frequency determined by
    the site or Program Management Office (PMO).

    Obtain the list of available package security updates from Red Hat. The URL
    for updates is https://rhn.redhat.com/errata/. It is important to note that
    updates provided by Red Hat may not be present on the system if the underlying
    packages are not installed.

    Check that the available package security updates have been installed on
    the system with the following command:

        $ sudo yum history list | more

        Loaded plugins: langpacks, product-id, subscription-manager
        ID | Command line | Date and time | Action(s) | Altered

    -------------------------------------------------------------------------------
        70 | install aide | 2020-03-05 10:58 | Install | 1
        69 | update -y | 2020-03-04 14:34 | Update | 18 EE
        68 | install vlc | 2020-02-21 17:12 | Install | 21
        67 | update -y | 2020-02-21 17:04 | Update | 7 EE

    If package updates have not been performed on the system within the
    timeframe the site/program documentation requires, this is a finding.

    Typical update frequency may be overridden by Information Assurance
    Vulnerability Alert (IAVA) notifications from CYBERCOM.

    If the operating system is in non-compliance with the Information Assurance
    Vulnerability Management (IAVM) process, this is a finding.'
  desc 'fix', 'Install the operating system patches or updated packages
    available from Red Hat within 30 days or sooner as local policy dictates.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230222'
  tag rid: 'SV-257778r627750_rule'
  tag stig_id: 'RHEL-08-010010'
  tag fix_id: 'F-32866r567413_fix'
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
