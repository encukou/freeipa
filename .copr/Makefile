srpm:
	# Setup development environment
	echo "Installing base development environment"
	dnf install -y dnf-plugins-core
	echo "Installing FreeIPA development dependencies"
	dnf builddep -y --spec freeipa.spec.in --best --allowerasing --setopt=install_weak_deps=False

	# Run autoconf
	autoreconf -i
	./configure --enable-silent-rules

	# Generate SRPMS
	make srpms

	if [[ "${outdir}" != "" ]]; then \
		mv rpmbuild/SRPMS/* ${outdir}; \
	fi
