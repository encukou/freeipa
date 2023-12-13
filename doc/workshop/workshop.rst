.. _workshop:

  Copyright 2015, 2016  Red Hat, Inc.

  This work is licensed under the Creative Commons Attribution 4.0
  International License. To view a copy of this license, visit
  http://creativecommons.org/licenses/by/4.0/.


Introduction
============

FreeIPA_ is a centralised identity management system.  In this
workshop you will learn how to deploy FreeIPA servers and enrol
client machines, define and manage user and service identities, set
up access policies, configure network services to take advantage of
FreeIPA's authentication and authorisation facilities and issue
X.509 certificates for services.

.. _FreeIPA: http://www.freeipa.org/page/Main_Page

.. _curriculum-overview:

Curriculum overview
-------------------

Mandatory:

- :ref:`Unit 1: Installing the FreeIPA server <1-server-install>`
- :ref:`Unit 2: Enrolling client machines <2-client-install>`
- :ref:`Unit 3: User management and Kerberos authentication <3-user-management>`
- :ref:`Unit 4: Host-based access control (HBAC) <4-hbac>`

Optional units—choose the topics that are relevant to you:

- :ref:`Unit 5: Web application authentication and authorisation <5-web-app-authnz>`
- :ref:`Unit 6: Service certificates <6-cert-management>`
- :ref:`Unit 7: Replica installation <7-replica-install>`
- :ref:`Unit 8: Sudo rule management <8-sudorule>`
- :ref:`Unit 9: SELinux User Maps <9-selinux-user-map>`
- :ref:`Unit 10: SSH user and host key management <10-ssh-key-management>`
- :ref:`Unit 11: Kerberos ticket policy <11-kerberos-ticket-policy>`
- :ref:`Unit 12: External IdP support <12-external-idp-support>`

Editing files on VMs
--------------------

Parts of the workshop involve editing files on virtual
machines.  The ``vi`` and GNU ``nano`` editors are available on the
VMs.  If you are not familiar with ``vi`` or you are unsure of what to use, you
should choose ``nano``.


Example commands
----------------

This guide contains many examples of commands.  Some of the commands
should be executed on your host, others on a particular guest VM.
For clarity, commands are annotated with the host on which they are
meant to be executed, as in these examples::

  $ echo "Run it on virtualisation host (no annotation)"

  [server]$ echo "Run it on FreeIPA server"

  [client]$ echo "Run it on IPA-enrolled client"

  ...


Preparation
===========

Some preparation is needed prior to the workshop.  The workshop is
designed to be carried out in a Vagrant_ environment that configures
three networked virtual machines (VMs) with all software needed for
the workshop.  **The goal of this preparation** is to ``vagrant up``
the VMs.  After this preparation is completed you are ready to begin
the workshop.

.. _Vagrant: https://www.vagrantup.com/


Requirements
------------

For the FreeIPA workshop you will need to:

- Install **Vagrant** and **VirtualBox**. (On Fedora, you can use **libvirt**
  instead of VirtualBox).

- Use Git to clone the repository containing the ``Vagrantfile``

- Fetch the Vagrant *box* for the workshop

- Add entries for the guest VMs to your hosts file (so you can
  access them by their hostname)

Please set up these items **prior to the workshop**.  More detailed
instructions follow.


Install Vagrant and VirtualBox
------------------------------

Fedora
^^^^^^

If you intend to use the ``libvirt`` provider (recommended), install
``vagrant-libvirt`` and ``vagrant-libvirt-doc``::

  $ sudo dnf install -y vagrant-libvirt vagrant-libvirt-doc

Also ensure you have the latest versions of ``selinux-policy`` and
``selinux-policy-targeted``.

Allow your regular user ID to start and stop Vagrant boxes using ``libvirt``.
Add your user to ``libvirt`` group so you don't need to enter your administrator
password everytime::

  $ sudo gpasswd -a ${USER} libvirt
  $ newgrp libvirt

Finally restart the services::

  $ systemctl restart libvirtd

More information: https://docs.fedoraproject.org/en-US/quick-docs/getting-started-with-virtualization/

Otherwise, you will use VirtualBox and the ``virtualbox`` provider.
VirtualBox needs to build kernel modules, and that means that you must
first install kernel headers and Dynamic Kernel Module Support::

  $ sudo dnf install -y vagrant kernel-devel dkms

Next, install VirtualBox from the official VirtualBox package repository.
Before using the repo, check that its contents match what appears
in the transcript below (to make sure it wasn't tampered with)::

  $ sudo curl -o /etc/yum.repos.d/virtualbox.repo \
    http://download.virtualbox.org/virtualbox/rpm/fedora/virtualbox.repo

  $ cat /etc/yum.repos.d/virtualbox.repo
  [virtualbox]
  name=Fedora $releasever - $basearch - VirtualBox
  baseurl=http://download.virtualbox.org/virtualbox/rpm/fedora/$releasever/$basearch
  enabled=1
  gpgcheck=1
  repo_gpgcheck=1
  gpgkey=https://www.virtualbox.org/download/oracle_vbox.asc

  $ sudo dnf install -y VirtualBox-6.1

Finally, load the kernel modules (you may need to restart your system for this to work)::

  $ sudo modprobe vboxdrv vboxnetadp


Mac OS X
^^^^^^^^

Install Vagrant for Mac OS X from
https://www.vagrantup.com/downloads.html.

Install VirtualBox 6.1 for **OS X hosts** from
https://www.virtualbox.org/wiki/Downloads.

Install Git from https://git-scm.com/download/mac or via your
preferred package manager.


Debian / Ubuntu
^^^^^^^^^^^^^^^

Install Vagrant, Git and VirtualBox::

  $ sudo apt-get install -y vagrant git
  $ sudo apt-get install -y virtualbox-6.1

If VirtualBox 6.1 was not available in the official packages for
your release, follow the instructions at
https://www.virtualbox.org/wiki/Linux_Downloads to install it.


Windows
^^^^^^^

Install Vagrant via the ``.msi`` available from
https://www.vagrantup.com/downloads.html.

Install VirtualBox for **Windows hosts** from
https://www.virtualbox.org/wiki/Downloads.

You will also need to install an SSH client, and Git.  Git for
Windows also comes with an SSH client so just install Git from
https://git-scm.com/download/win.


Clone this repository
---------------------

This repository contains the ``Vagrantfile`` that is used for the
workshop, which you will need locally.

::

  $ git clone https://github.com/freeipa/freeipa.git
  $ cd freeipa/doc/workshop


Fetch Vagrant box
-----------------

Please fetch the Vagrant box prior to the workshop.  It is > 500MB
so it may not be feasible to download it during the workshop.

::

  $ vagrant box add fedora/39-cloud-base


Add hosts file entries
----------------------

*This step is optional.  All units can be completed using the CLI
only.  But if you want to access the FreeIPA Web UI or other web
servers on the VMs from your browser, follow these instructions.*

Add the following entries to your hosts file::

  192.168.33.10   server.ipademo.local
  192.168.33.11   replica.ipademo.local
  192.168.33.20   client.ipademo.local

On Unix systems (including Mac OS X), the hosts file is ``/etc/hosts``
(you need elevated permissions to edit it.)

On Windows, edit ``C:\Windows\System32\system\drivers\etc\hosts`` as
*Administrator*.


Next step
---------

You are ready to begin the workshop.  Continue to
:ref:`Unit 1: Installing the FreeIPA server <1-server-install>`.


After the workshop
------------------

Here are some contact details and resources that may help you after
the workshop is over:

- IRC: ``#freeipa`` and ``#sssd`` (Libera.chat)

- ``freeipa-users@lists.fedorahosted.org`` `mailing list
  <https://lists.fedoraproject.org/archives/list/freeipa-users@lists.fedorahosted.org/>`_

- `How To guides <https://www.freeipa.org/page/HowTos>`_: large
  index of articles about specialised tasks and integrations

- `Troubleshooting guide
  <https://www.freeipa.org/page/Troubleshooting>`_: how to debug
  common problems; how to report bugs

- `Bug tracker <https://pagure.io/freeipa>`_

- Information about the `FreeIPA public demo
  <https://www.freeipa.org/page/Demo>`_ instance

- `Deployment Recommendations
  <https://www.freeipa.org/page/Deployment_Recommendations>`_:
  things to consider when going into production

- `Documentation index
  <https://www.freeipa.org/page/Documentation>`_

- `FreeIPA Planet <http://planet.freeipa.org/>`_: aggregate of
  several FreeIPA and identity-management related blogs

- `GitHub organisation <https://github.com/freeipa>`_.  In addition
  to the `main repository <https://github.com/freeipa/freeipa>`_
  there are various tools, CI-related projects and documentation.

- `Development roadmap <https://www.freeipa.org/page/Roadmap>`_
