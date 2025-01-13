#!/bin/sh

die() {
    >&2 echo $*
    exit 1
}

detach() {
    nohup "$@" >/dev/null 2>&1 </dev/null &
}

grep -q "Name=ipa-workshop" ~/.mozilla/firefox/profiles.ini || die "Firefox profile 'ipa-workshop' not found."

detach podman unshare --rootless-netns firefox -P ipa-workshop --new-instance --new-window "$@"
