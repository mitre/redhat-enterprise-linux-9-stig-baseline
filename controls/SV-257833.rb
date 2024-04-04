control 'SV-257833' do
  title 'The iprutils package must not be installed unless mission essential on
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

    The iprutils package provides a suite of utilities to manage and configure
SCSI devices supported by the ipr SCSI storage device driver.'
  desc 'check', 'Verify the iprutils package has not been installed on the system with the
following commands:

    $ sudo yum list installed iprutils

    iprutils.x86_64
2.4.18.1-1.el8                                                  @anaconda

    If the iprutils package is installed and is not documented with the
Information System Security Officer (ISSO) as an operational requirement, this
is a finding.'
  desc 'fix', 'Document the iprutils package with the ISSO as an operational requirement
or remove it from the system with the following command:

    $ sudo yum remove iprutils'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230560'
  tag rid: 'SV-257833r627750_rule'
  tag stig_id: 'RHEL-08-040380'
  tag fix_id: 'F-33204r568427_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  if input('iprutils_required')
    describe package('iprutils') do
      it { should be_installed }
    end
  else
    describe package('iprutils') do
      it { should_not be_installed }
    end
  end
end
