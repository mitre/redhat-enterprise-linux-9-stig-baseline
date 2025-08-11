control 'SV-257879' do
  title 'RHEL 9 local disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection.'
  desc 'RHEL 9 systems handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).'
  desc 'check', 'Note: If there is a documented and approved reason for not having data-at-rest encryption at the operating system level, such as encryption provided by a hypervisor or a disk storage array in a virtualized environment, this requirement is Not Applicable.

Verify RHEL 9 prevents unauthorized disclosure or modification of all information requiring at-rest protection by using disk encryption. 

Note: If there is a documented and approved reason for not having data-at-rest encryption, this requirement is Not Applicable.

List all block devices in tree-like format:

$ sudo lsblk --tree

NAME                       MAJ:MIN  RM   SIZE     RO    TYPE    MOUNTPOINTS
zram0                      252:0    0    8G       0     disk    [SWAP]
nvme0n1                    259:0    0    476.9G   0     disk
|-nvme0n1p1                259:1    0    1G       0     part    /boot/efi
|-nvme0n1p2                259:2    0    1G       0     part    /boot
|-nvme0n1p3                259:3    0    474.9G   0     part
  |-luks-<encrypted_id>    253:0    0    474.9G   0     crypt
    |-rhel-root            253:1    0    16G      0     lvm     /
    |-rhel-varcache        253:2    0    8G       0     lvm     /var/cache
    |-rhel-vartmp          253:3    0    4G       0     lvm     /var/tmp
    |-rhel-varlog          253:4    0    4G       0     lvm     /var/log
    |-rhel-home            253:5    0    64G      0     lvm     /home
    |-rhel-varlogaudit     253:6    0    4G       0     lvm     /var/log/audit

Verify that the block device tree for each persistent filesystem, excluding the /boot and /boot/efi filesystems, has at least one parent block device of type "crypt", and that the encryption type is LUKS:

$ sudo cryptsetup status luks-b74f6910-2547-4399-86b2-8b0252d926d7
/dev/mapper/luks-b74f6910-2547-4399-86b2-8b0252d926d7 is active and is in use.
  type:    LUKS2
  cipher:  aes-xts-plain64
  keysize: 512 bits
  key location: keyring
  device:  /dev/nvme0n1p3
  sector size:  512
  offset:  32768 sectors
  size:    995986063 sectors
  mode:    read/write

If there are persistent filesystems (other than /boot or /boot/efi) whose block device trees do not have a crypt block device of type LUKS, ask the administrator to indicate how persistent filesystems are encrypted. 

If there is no evidence that persistent filesystems are encrypted, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to prevent unauthorized modification of all information at rest by using disk encryption.

Encrypting a partition in an already installed system is more difficult, because existing partitions will need to be resized and changed.

To encrypt an entire partition, dedicate a partition for encryption in the partition layout.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000405-GPOS-00184'
  tag satisfies: ['SRG-OS-000185-GPOS-00079', 'SRG-OS-000404-GPOS-00183', 'SRG-OS-000405-GPOS-00184']
  tag gid: 'V-257879'
  tag rid: 'SV-257879r1045454_rule'
  tag stig_id: 'RHEL-09-231190'
  tag fix_id: 'F-61544r925623_fix'
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-28 (1)']
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
  elsif input('data_at_rest_exempt')
    impact 0.0
    describe_and_skip('Data At Rest Requirements have been set to Not Applicabe by the `data_at_rest_exempt` input.')
  elsif all_args.empty?
    # TODO: Determine if this is an NA vs and NR or even a pass
    describe_and_skip('Command blkid did not return and non-psuedo block devices.')
  else
    unencrypted_drives = all_args.reject { |a| a.match(/\bcrypto_LUKS\b/) || 
      input('luks_exceptions').include?(a.split(':').first) ||
      a.split(':').first.match(%r{^/dev/mapper/})
    }
    describe 'All local disk partitions' do
      it 'should be encrypted with crypto_LUKS' do
        expect(unencrypted_drives).to be_empty, "The following partitions are not encrypted with crypto_LUKS:\t\n- #{unencrypted_drives.join("\t\n- ")}"
      end
    end
  end
end
