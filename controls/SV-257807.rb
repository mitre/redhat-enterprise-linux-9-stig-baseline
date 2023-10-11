control 'SV-257807' do
  title 'RHEL 9 must disable the Stream Control Transmission Protocol (SCTP) kernel module.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect unused protocols can result in a system compromise.

The Stream Control Transmission Protocol (SCTP) is a transport layer protocol, designed to support the idea of message-oriented communication, with several streams of messages within one connection. Disabling SCTP protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'Verify that RHEL 9 disables the ability to load the sctp kernel module with the following command:

$ sudo grep -r sctp /etc/modprobe.conf /etc/modprobe.d/* 

blacklist sctp

If the command does not return any output, or the line is commented out, and use of sctp is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'To configure the system to prevent the sctp kernel module from being loaded, add the following line to the file  /etc/modprobe.d/sctp.conf (or create sctp.conf if it does not exist):

install sctp/bin/false
blacklist sctp'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61548r925406_chk'
  tag severity: 'medium'
  tag gid: 'V-257807'
  tag rid: 'SV-257807r925408_rule'
  tag stig_id: 'RHEL-09-213060'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-61472r925407_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
