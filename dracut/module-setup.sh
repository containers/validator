#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
#
# Copyright (C) 2023 Alexander Larsson <alexl@redhat.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library. If not, see <https://www.gnu.org/licenses/>.

check() {
    if [[ -x /usr/bin/validator ]]; then
       return 255
    fi

    return 1
}

depends() {
    return 0
}

install() {
    dracut_install /usr/bin/validator
    for r in /usr/lib /etc; do
        inst_multiple -o "$r/validator/boot.d/*.conf" "$r/validator/keys/*"
    done
    inst_simple "${moddir}/validator-boot.service" "${systemdsystemunitdir}/validator-boot.service"
    $SYSTEMCTL -q --root "$initdir" add-wants initrd.target validator-boot.service
}
