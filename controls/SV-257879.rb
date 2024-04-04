control 'SV-257879' do
  title 'All RHEL 8 local disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection.'
  desc 'RHEL 8 systems handling data requiring "data at rest" protections
    must employ cryptographic mechanisms to prevent unauthorized disclosure and
    modification of the information at rest.

    Selection of a cryptographic mechanism is based on the need to protect the
integrity of organizational information. The strength of the mechanism is
commensurate with the security category and/or classification of the
information. Organizations have the flexibility to either encrypt all
information on storage devices (i.e., full disk encryption) or encrypt specific
data structures (e.g., files, records, or fields).'
  desc 'check', 'Verify RHEL 8 prevents unauthorized disclosure or modification of all information requiring at-rest protection by using disk encryption.

If there is a documented and approved reason for not having data-at-rest encryption at the operating system level, such as encryption provided by a hypervisor or a disk storage array in a virtualized environment, this requirement is not applicable.

Verify all system partitions are encrypted with the following command:

     $ sudo blkid

     /dev/mapper/rhel-root:  UUID="67b7d7fe-de60-6fd0-befb-e6748cf97743" TYPE="crypto_LUKS"

Every persistent disk partition present must be of type "crypto_LUKS". If any partitions other than the boot partition or pseudo file systems (such as /proc or /sys) are not type "crypto_LUKS", ask the administrator to indicate how the partitions are encrypted.

If there is no evidence that these partitions are encrypted, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to prevent unauthorized modification of all information at
rest by using disk encryption.

    Encrypting a partition in an already installed system is more difficult,
    because existing partitions will need to be resized and changed. To encrypt an
    entire partition, dedicate a partition for encryption in the partition layout.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag satisfies: ['SRG-OS-000185-GPOS-00079', 'SRG-OS-000404-GPOS-00183', 'SRG-OS-000405-GPOS-00184']
  tag gid: 'V-230224'
  tag rid: 'SV-257879r917864_rule'
  tag stig_id: 'RHEL-08-010030'
  tag fix_id: 'F-32868r567419_fix'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
  tag 'host'

  all_args = command('blkid').stdout.strip.split("\n").map { |s| s.sub(/^"(.*)"$/, '\1') }

  def describe_and_skip(message)
    describe message do
      skip message
    end
  end

  # TODO: This should really have a resource

  if virtualization.system.eql?('docker')
    impact 0.0
    describe_and_skip('Disk Encryption and Data At Rest Implementation is handled on the Container Host')
  elsif input('data_at_rest_exempt') == true
    impact 0.0
    describe_and_skip('Data At Rest Requirements have been set to Not Applicabe by the `data_at_rest_exempt` input.')
  elsif all_args.empty?
    # TODO: Determine if this is an NA vs and NR or even a pass
    describe_and_skip('Command blkid did not return and non-psuedo block devices.')
  else
    all_args.each do |args|
      describe args do
        it { should match(/\bcrypto_LUKS\b/) }
      end
    end
  end
end
