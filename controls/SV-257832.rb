control 'SV-257832' do
  title 'The gssproxy package must not be installed unless mission essential on
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

    The gssproxy package is a proxy for GSS API credential handling and could
expose secrets on some networks. It is not needed for normal function of the OS.'
  desc 'check', 'Verify the gssproxy package has not been installed on the system with the
following commands:

    $ sudo yum list installed gssproxy

    gssproxy.x86_64
0.8.0-14.el8                                                  @anaconda

    If the gssproxy package is installed and is not documented with the
Information System Security Officer (ISSO) as an operational requirement, this
is a finding.'
  desc 'fix', 'Document the gssproxy package with the ISSO as an operational requirement
or remove it from the system with the following command:

    $ sudo yum remove gssproxy'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230559'
  tag rid: 'SV-257832r646887_rule'
  tag stig_id: 'RHEL-08-040370'
  tag fix_id: 'F-33203r568424_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'
  tag 'container'

  if input('gssproxy_required')
    describe package('gssproxy') do
      it { should be_installed }
    end
  else
    describe package('gssproxy') do
      it { should_not be_installed }
    end
  end
end
