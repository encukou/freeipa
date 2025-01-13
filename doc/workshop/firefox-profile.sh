#!/bin/sh

MOZILLA_PROFILES="${HOME}/.mozilla/firefox/profiles.ini"
WORKSHOP_PROFILE_DIR="${HOME}/.mozilla/firefox/ipa-workshop"

if [ "$1" == "clean" ]
then
    sed -i "/^\# start - Added by FreeIPA Workshop$/,/^\# end - Added by FreeIPA Workshop/d" "${MOZILLA_PROFILES}"
    rm -rf "${WORKSHOP_PROFILE_DIR}"
    exit
fi

if [ ! -d "${WORKSHOP_PROFILE_DIR}" ]
then
    mkdir "${WORKSHOP_PROFILE_DIR}"
    certutil -N -d "${WORKSHOP_PROFILE_DIR}"
    podman cp server:/etc/ipa/ca.crt "${WORKSHOP_PROFILE_DIR}/ca.crt"
    certutil -A -i "${WORKSHOP_PROFILE_DIR}/ca.crt" -d "${WORKSHOP_PROFILE_DIR}" -n 'Certificate Authority - IPADEMO.LOCAL' -t "CT,C,"
fi

if ! grep -q "Name=ipa-workshop" "${MOZILLA_PROFILES}"
then
    next_profile=$(echo $(($(cat "${MOZILLA_PROFILES}" | sed -n 's/\[Profile\([^\]]*\)\]/\1/p' | sort -n | tail -n 1) + 1)))

    cat >> "${MOZILLA_PROFILES}" <<EOF
# start - Added by FreeIPA Workshop
[Profile${next_profile}]
Name=ipa-workshop
IsRelative=1
Path=ipa-workshop
# end - Added by FreeIPA Workshop
EOF

fi
