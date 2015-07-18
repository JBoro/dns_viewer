# Copyright 1999-2015 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=5

inherit eutils fcaps cmake-utils git-2

DESCRIPTION="Quick Easy DNS viewer"
HOMEPAGE="https://github.com/JBoro/dns_viewer"
SRC_URI=""
EGIT_REPO_URI="https://github.com/JBoro/dns_viewer.git"
EGIT_COMMIT="328009cf2911cdb9c88c92fbfd22237f4d1dab06"

LICENSE="ISC"
SLOT="0"
KEYWORDS="~amd64"
IUSE=""

RDEPEND="net-libs/libpcap"
DEPEND="${RDEPEND}
        dev-qt/qtcore:4
        dev-qt/qtgui:4
        x11-misc/xdg-utils"

CMAKE_USE_DIR="${S}/src"

src_configure() {
        cmake-utils_src_configure
}

src_compile() {
        cmake-utils_src_make
}

src_install() {
        cmake-utils_src_install
        domenu dnsviewer.desktop
}

pkg_postinst() {
        fcaps cap_net_raw \
            "${EROOT}"/usr/bin/dnsviewer
}
