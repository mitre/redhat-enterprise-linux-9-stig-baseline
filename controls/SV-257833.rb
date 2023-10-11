control 'SV-257833' do
  title 'RHEL 9 must not have the iprutils package installed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

The iprutils package provides a suite of utilities to manage and configure SCSI devices supported by the ipr SCSI storage device driver.

'
  desc 'check', 'Verify that the iprutils package is not installed with the following command:

$ sudo dnf list --installed iprutils

Error: No matching Packages to list

If the "iprutils" package is installed and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Remove the iprutils package with the following command:

$ sudo dnf remove iprutils'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61574r925484_chk'
  tag severity: 'medium'
  tag gid: 'V-257833'
  tag rid: 'SV-257833r925486_rule'
  tag stig_id: 'RHEL-09-215050'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-61498r925485_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-7 a']
end
