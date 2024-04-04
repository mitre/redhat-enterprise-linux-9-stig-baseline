control 'SV-257827' do
  title 'RHEL 8 must not have the sendmail package installed.'
  desc 'It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Operating systems are capable of providing a wide variety of functions and
services. Some of the functions and services, provided by default, may not be
necessary to support essential organizational operations (e.g., key missions,
functions).

    Examples of non-essential capabilities include, but are not limited to,
games, software packages, tools, and demonstration software not related to
requirements or providing a wide array of functionality not required for every
mission, but which cannot be disabled.

    Verify the operating system is configured to disable non-essential
capabilities. The most secure way of ensuring a non-essential capability is
disabled is to not have the capability installed.'
  desc 'check', 'Check to see if the sendmail package is installed with the following
command:

    $ sudo yum list installed sendmail

    If the sendmail package is installed, this is a finding.'
  desc 'fix', 'Configure the operating system to disable non-essential capabilities by
removing the sendmail package from the system with the following command:

    $ sudo yum remove sendmail'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-230489'
  tag rid: 'SV-257827r627750_rule'
  tag stig_id: 'RHEL-08-040002'
  tag fix_id: 'F-33133r568214_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'
  tag 'container'

  describe package('sendmail') do
    it { should_not be_installed }
  end
end
