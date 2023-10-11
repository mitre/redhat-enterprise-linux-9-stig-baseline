control 'SV-257879' do
  title 'RHEL 9 local disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection.'
  desc 'RHEL 9 systems handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

'
  desc 'check', 'Verify RHEL 9 prevents unauthorized disclosure or modification of all information requiring at-rest protection by using disk encryption. 

Note: If there is a documented and approved reason for not having data-at-rest encryption, this requirement is Not Applicable.

Verify all system partitions are encrypted with the following command:

$ blkid

/dev/map per/rhel-root:  UUID="67b7d7fe-de60-6fd0-befb-e6748cf97743" TYPE="crypto_LUKS"

Every persistent disk partition present must be of type "crypto_LUKS". If any partitions other than the boot partition or pseudo file systems (such as /proc or /sys) or temporary file systems (that are tmpfs) are not type "crypto_LUKS", ask the administrator to indicate how the partitions are encrypted.  If there is no evidence that these partitions are encrypted, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to prevent unauthorized modification of all information at rest by using disk encryption.

Encrypting a partition in an already installed system is more difficult, because existing partitions will need to be resized and changed.

To encrypt an entire partition, dedicate a partition for encryption in the partition layout.'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61620r925622_chk'
  tag severity: 'high'
  tag gid: 'V-257879'
  tag rid: 'SV-257879r925624_rule'
  tag stig_id: 'RHEL-09-231190'
  tag gtitle: 'SRG-OS-000405-GPOS-00184'
  tag fix_id: 'F-61544r925623_fix'
  tag satisfies: ['SRG-OS-000405-GPOS-00184', 'SRG-OS-000185-GPOS-00079', 'SRG-OS-000404-GPOS-00183']
  tag 'documentable'
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-28 (1)', 'SC-28 (1)']
end
