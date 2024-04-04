control 'SV-257952' do
  title 'The Trivial File Transfer Protocol (TFTP) server package must not be
installed if not required for RHEL 8 operational support.'
  desc 'If TFTP is required for operational support (such as the transmission
of router configurations) its use must be documented with the Information
System Security Officer (ISSO), restricted to only authorized personnel, and
have access control rules established.'
  desc 'check', 'Verify a TFTP server has not been installed on the system with the
following command:

    $ sudo yum list installed tftp-server

    tftp-server.x86_64   5.2-24.el8

    If TFTP is installed and the requirement for TFTP is not documented with
the ISSO, this is a finding.'
  desc 'fix', 'Remove the TFTP package from the system with the following command:

$ sudo yum remove tftp-server'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230533'
  tag rid: 'SV-257952r627750_rule'
  tag stig_id: 'RHEL-08-040190'
  tag fix_id: 'F-33177r568346_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  if input('tftp_required')
    describe package('tftp-server') do
      it { should be_installed }
    end
  else
    describe package('tftp-server') do
      it { should_not be_installed }
    end
  end
end
