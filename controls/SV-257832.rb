control 'SV-257832' do
  title 'RHEL 9 must not have the gssproxy package installed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore, may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations (e.g., key missions, functions).

The gssproxy package is a proxy for GSS API credential handling and could expose secrets on some networks. It is not needed for normal function of the OS.'
  desc 'check', 'Verify that the gssproxy package is not installed with the following command:

$ sudo dnf list --installed gssproxy

Error: No matching Packages to list

If the "gssproxy" package is installed and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Remove the gssproxy package with the following command:

$ sudo dnf remove gssproxy'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-257832'
  tag rid: 'SV-257832r925483_rule'
  tag stig_id: 'RHEL-09-215045'
  tag fix_id: 'F-61497r925482_fix'
  tag cci: ['CCI-000381', 'CCI-000366']
  tag nist: ['CM-7 a', 'CM-6 b']
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
