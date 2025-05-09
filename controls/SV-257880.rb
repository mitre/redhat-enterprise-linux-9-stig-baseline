control 'SV-257880' do
  title 'RHEL 9 must disable mounting of cramfs.'
  desc 'It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Removing support for unneeded filesystem types reduces the local attack
surface of the server.

    Compressed ROM/RAM file system (or cramfs) is a read-only file system
designed for simplicity and space-efficiency.  It is mainly used in embedded
and small-footprint systems.'
  desc 'check', 'Verify that RHEL 9 disables the ability to load the cramfs kernel module with the following command:

$ grep -r cramfs /etc/modprobe.conf /etc/modprobe.d/* 

install cramfs /bin/false
blacklist cramfs

If the command does not return any output or the lines are commented out, and use of cramfs is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'To configure the system to prevent the cramfs kernel module from being loaded, add the following lines to the file /etc/modprobe.d/blacklist.conf (or create blacklist.conf if it does not exist):

install cramfs /bin/false
blacklist cramfs'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-257880'
  tag rid: 'SV-257880r1044951_rule'
  tag stig_id: 'RHEL-09-231195'
  tag fix_id: 'F-61545r1044950_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  describe kernel_module('cramfs') do
    it { should be_disabled }
    it { should be_blacklisted }
  end
end
