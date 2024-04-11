#!/bin/bash
# Import DoD root certificates into linux CA store
# https://gist.github.com/AfroThundr3007730/ba99753dda66fc4abaf30fb5c0e5d012

main() {
    # Location of bundle from DISA site
    url='https://public.cyber.mil/pki-pke/pkipke-document-library/'
    bundle=$(curl -s $url | awk -F '"' 'tolower($2) ~ /dod.zip/ {print $2}')
    #bundle=https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/certificates_pkcs7_v5-6_dod.zip

    # Set cert directory and update command based on OS
    source /etc/os-release
    if [[ $ID =~ (fedora|rhel|centos) ||
        $ID_LIKE =~ (fedora|rhel|centos) ]]; then
        certdir=/etc/pki/ca-trust/source/anchors
        update=update-ca-trust
    elif [[ $ID =~ (debian|ubuntu|mint) ||
        $ID_LIKE =~ (debian|ubuntu|mint) ]]; then
        certdir=/usr/local/share/ca-certificates
        update=update-ca-certificates
    else
        certdir=$1
        update=$2
    fi

    [[ -n $certdir && -n $update ]] || {
        echo 'Unable to autodetect OS using /etc/os-release.'
        echo 'Please provide CA certificate directory and update command.'
        echo 'Example: add-dod-certs.sh /cert/store/location update-cmd'
        exit 1
    }

    # Extract the bundle
    cd $certdir
    wget -qP tmp $bundle
    unzip -qj tmp/${bundle##*/} -d tmp

    # Check for existence of PEM format p7b.
    if [ -f "tmp/*_dod_pem.p7b" ]; then
        echo 'Found PEM formatted file, continuing extraction...'
        certform="PEM"
        certfile="*_dod_pem.p7b"
    else
        echo 'Found DER formatted file, continuing extraction and conversion...'
        certform="DER"
        certfile="*_dod_der.p7b"
    fi

    # Convert the PKCS#7 bundle into individual PEM files
    openssl pkcs7 -inform ${certform} -print_certs -in tmp/${certfile} |
        awk 'BEGIN {c=0} /subject=/ {c++} {print > "cert." c ".pem"}'

    # Rename the files based on the CA name
    for i in *.pem; do
        name=$(
            openssl x509 -noout -subject -in $i |
                awk -F '(=|= )' '{gsub(/ /, "_", $NF); print $NF}'
        )
        mv $i ${name}.crt
    done

    # Remove temp files and update certificate stores
    rm -fr tmp
    $update
}

# Only execute if not being sourced
[[ ${BASH_SOURCE[0]} == "$0" ]] && main "$@"
