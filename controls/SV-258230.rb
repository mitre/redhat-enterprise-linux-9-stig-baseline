control 'SV-258230' do
  title 'RHEL 8 must implement NIST FIPS-validated cryptography for the following: To provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

RHEL 8 utilizes GRUB 2 as the default bootloader. Note that GRUB 2 command-line parameters are defined in the "kernelopts" variable of the /boot/grub2/grubenv file for all kernel boot entries. The command "fips-mode-setup" modifies the "kernelopts" variable, which in turn updates all kernel boot entries.

The fips=1 kernel option needs to be added to the kernel command line during system installation so that key generation is done with FIPS-approved algorithms and continuous monitoring tests in place. Users must also ensure the system has plenty of entropy during the installation process by moving the mouse around, or if no mouse is available, ensuring that many keystrokes are typed. The recommended amount of keystrokes is 256 and more. Less than 256 keystrokes may generate a nonunique key.'
  desc 'check', 'Verify the operating system implements DOD-approved encryption to protect the confidentiality of remote access sessions.

Check to see if FIPS mode is enabled with the following command:

     $ fips-mode-setup --check
     FIPS mode is enabled

If FIPS mode is "enabled", check to see if the kernel boot parameter is configured for FIPS mode with the following command:

     $ sudo grub2-editenv list | grep fips
     kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82

If the kernel boot parameter is configured to use FIPS mode, check to see if the system is in FIPS mode with the following command:

     $ sudo cat /proc/sys/crypto/fips_enabled
     1

If FIPS mode is not "on", the kernel boot parameter is not configured for FIPS mode, or the system does not have a value of "1" for "fips_enabled" in "/proc/sys/crypto", this is a finding.'
  desc 'fix', 'Configure the operating system to implement DOD-approved encryption by following the steps below:

To enable strict FIPS compliance, the fips=1 kernel option needs to be added to the kernel boot parameters during system installation so key generation is done with FIPS-approved algorithms and continuous monitoring tests in place.

Enable FIPS mode after installation (not strict FIPS-compliant) with the following command:

     $ sudo fips-mode-setup --enable

Reboot the system for the changes to take effect.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000396-GPOS-00176', 'SRG-OS-000423-GPOS-00187', 'SRG-OS-000478-GPOS-00223']
  tag gid: 'V-230223'
  tag rid: 'SV-258230r928585_rule'
  tag stig_id: 'RHEL-08-010020'
  tag fix_id: 'F-32867r928584_fix'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable in a container' do
      skip 'The host OS controls the FIPS mode settings. The host OS should also be scanned with the applicable OS validation profile.'
    end
  elsif input('use_fips') == false
    impact 0.0
    describe 'This control is Not Applicable as FIPS is not required for this system' do
      skip 'This control is Not Applicable as FIPS is not required for this system'
    end
  else
    describe command('fips-mode-setup --check') do
      its('stdout.strip') { should match(/FIPS mode is enabled/) }
    end

    grub_config = command('grub2-editenv - list').stdout

    describe parse_config(grub_config) do
      its('kernelopts') { should match(/fips=1/) }
    end

    describe file('/proc/sys/crypto/fips_enabled') do
      its('content.strip') { should cmp '1' }
    end
  end
end
