control 'SV-257834' do
  title 'RHEL 9 must not have the tuned package installed.'
  desc 'It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Operating systems are capable of providing a wide variety of functions and
services. Some of the functions and services, provided by default, may not be
necessary to support essential organizational operations (e.g., key missions,
functions).

    The tuned package contains a daemon that tunes the system settings
dynamically. It does so by monitoring the usage of several system components
periodically. Based on that information, components will then be put into lower
or higher power savings modes to adapt to the current usage. The tuned package
is not needed for normal OS operations.'
  desc 'check', 'Verify that the tuned package is not installed with the following command:

$ dnf list --installed tuned

Error: No matching Packages to list

If the "tuned" package is installed and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Remove the tuned package with the following command:

$ sudo dnf remove tuned'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-257834'
  tag rid: 'SV-257834r1044904_rule'
  tag stig_id: 'RHEL-09-215055'
  tag fix_id: 'F-61499r925488_fix'
  tag cci: ['CCI-000366', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-7 a']
  tag 'host'
  tag 'container'

  if input('tuned_required')
    describe package('tuned') do
      it { should be_installed }
    end
  else
    describe package('tuned') do
      it { should_not be_installed }
    end
  end
end
