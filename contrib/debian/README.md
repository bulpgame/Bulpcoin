
Debian
====================
This directory contains files used to package bulpcoind/bulpcoin-qt
for Debian-based Linux systems. If you compile bulpcoind/bulpcoin-qt yourself, there are some useful files here.

## bulpcoin: URI support ##


bulpcoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install bulpcoin-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your bulpcoinqt binary to `/usr/bin`
and the `../../share/pixmaps/bulpcoin128.png` to `/usr/share/pixmaps`

bulpcoin-qt.protocol (KDE)

