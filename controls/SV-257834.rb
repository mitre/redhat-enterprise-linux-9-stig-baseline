control 'SV-257834' do
  title 'The tuned package must not be installed unless mission essential on
RHEL 8.'
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
  desc 'check', 'Verify the tuned package has not been installed on the system with the
following commands:

    $ sudo yum list installed tuned

    tuned.noarch
2.12.0-3.el8                                                  @anaconda

    If the tuned package is installed and is not documented with the
Information System Security Officer (ISSO) as an operational requirement, this
is a finding.'
  desc 'fix', 'Document the tuned package with the ISSO as an operational requirement or
remove it from the system with the following command:

    $ sudo yum remove tuned'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230561'
  tag rid: 'SV-257834r627750_rule'
  tag stig_id: 'RHEL-08-040390'
  tag fix_id: 'F-33205r568430_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
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
