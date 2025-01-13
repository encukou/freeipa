.. _workshop:

  Copyright 2015-2025 Red Hat, Inc.

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

Parts of the workshop involve editing files on virtual hosts.
The ``vi`` and GNU ``nano`` editors are available on the containers.


Example commands
----------------

This guide contains many examples of commands.  Some of the commands
should be executed on your host, others on a particular guest.
For clarity, commands are annotated with the host on which they are
meant to be executed, as in these examples::

  $ echo "Run it on virtualisation host (no annotation)"

  [server]$ echo "Run it on FreeIPA server"

  [client]$ echo "Run it on IPA-enrolled client"

  ...


Preparation
===========

Some preparation is needed prior to the workshop.  The workshop is
designed to be carried out in a container environment that configures
three networked hosts with all software needed for the workshop.
**The goal of this preparation** is to have the environment running
and ready to begin the workshop.


Requirements
------------

For the FreeIPA workshop you will need to use:

- ``git`` to clone the workshop repository

- ``ipalab-config`` to generate the configuration for the containers

- ``podman`` and ``podman-compose`` compose to control the containers

You'll also need Internet connection to download the container images.

Please set up these items **prior to the workshop**. Detailed instructions
for different platforms follow.


Starting the workshop environment
---------------------------------

Linux
^^^^^

On most modern Linux environments, ``python`` and ``pip`` are already
available. If not, use your prefered package manager to install both.

The other tools you may install through your package manager are ``podman``
and ``podman-compose``. As an alternative, both can be installed within a
Python virtual environment, as seen later.

See https://podman.io/docs/installation#installing-on-linux for
instructions on installing ``podman`` on several Linux distributions.


macOS and Windows
^^^^^^^^^^^^^^^^^

Follow the instructions to install ``podman`` from found at
https://podman.io/docs/installation

Running containers on macOS and Windows requires a virtual macine
running Linux to host the containers. ``podman`` makes the use of
this virtual machine nearly transparent.

The default virtual machine do not provide enough memory to run the
workshop environment. Create a new virtual machine with::

   $ podman machine init --memory 4096 ipa-workshop
   $ podman machine start ipa-workshop

Using 4GB of memory for the underlying virtual machine is close to the
minimum possible. The used memory for the containers right after the
deployment is around 2.5GB, and it does not take into account any usage
spike. If you have 16GB or more of RAM on your Mac machine, use, at
least, 6GB (``--memory 6144``) for the podman machine.

After this setup, test your ``podman`` environment by running
``podman run hello``.


Clone this repository
---------------------

This repository contains the base configuration files to generate the
workshop environment, which you will need locally.

::

  $ git clone https://github.com/freeipa/freeipa.git
  $ cd freeipa/doc/workshop


Create and run the container compose
------------------------------------

To be able to run the workshop environment, you'll have to install some
tools, and you can  isolate your environment form the one used for the
workshop, by creating and activating a Python environment::

  $ python3 -m venv /tmp/ipa-workshop
  $ source /tmp/ipa-workshop/bin/activate


Within the virtual environment, install the tools used to create and run
the container compose with::

  $ pip install -r requirements.txt

Now generate the workshop configuration environment dy issuing::

  $ ipalab-config ipa-workshop.yaml

Create a virtual network for the workshop::

  $ podman network create \
        --disable-dns \
        --subnet "192.168.33.0/24" \
        ipanet-workshop

Start the container compose::

  $ cd ipa-workshop-lab
  $ podman-compose up -d

Add the host entries to your host's '/etc/hosts' file with::

  $ sudo bash -c "cat hosts >> /etc/hosts"

If you prefer to do it manually, these are the required entries::

  192.168.33.2  server.ipademo.local
  192.168.33.3  replica.ipademo.local
  192.168.33.4  client.ipademo.local

Once you are done with the workshop, form the lab folder, you can
shutdown the environment with::

  $ podman-compose down


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
