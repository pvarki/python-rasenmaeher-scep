==============
MDM enrolment
==============

How a phone becomes a Deploy App user without anyone installing an application on it, and what
each part of the system is actually responsible for.

The shape
=========

An operator adds a phone to whatever MDM a unit already runs. The device generates its own key,
asks for a certificate over SCEP, and comes out of enrolment as a real user of the deployment.
Nothing of ours runs on the phone, and no private key ever leaves it.

Three things are involved and each knows as little as it can::

    device ──▶ MDM ──▶ /scep ──▶ rmscep ──▶ RASENMAEHER ──▶ deployment CA

The **MDM** proxies the request. On Android the phone never connects to us at all: the MDM's
server does, which is why the endpoint has to be publicly reachable and why requests arrive from
the MDM's addresses rather than the device's.

**rmscep** speaks SCEP and nothing else. It holds no roster, decides no policy, and knows no
product's package names. It unwraps the request and asks RASENMAEHER to enrol the device under the
name its MDM gave it.

**RASENMAEHER** owns the decision. It is the certificate authority, it knows whether enrolment is
open and whether a name is free, and it is the only component that can say yes.

Two containers, and why
=======================

``scepinit``
    Runs once, obtains the client identity signed by the deployment CA, exits. It exists purely so
    the long running responder never sits on the CA network, where anything can have a certificate
    signed for an arbitrary subject. That is not a privilege an internet facing parser should hold
    for its whole life.

``rmscep``
    The responder. Its only network neighbour is the front proxy, so it cannot reach the API
    directly and has no route to the CA. It reaches RASENMAEHER the way any other mTLS client does.

Neither holds an MDM API token. The commands that talk to an MDM are operator commands, run
deliberately, and the token is passed at run time. Something that can reach every device a unit
owns has no business also being an internet facing parser.

What authorises what
====================

Three things gate an enrolment, and it is worth being precise about what each is worth.

**The enrolment window** is the real gate. RASENMAEHER refuses every device until an admin opens
enrolment on the MDM page, and the window closes itself. Keep it open only while phones are being
enrolled.

**The SCEP challenge** keeps noise off the endpoint. It sits in the MDM's configuration and every
enrolled device carries it, so it cannot be treated as confidential: while the window is open,
whoever holds it can enrol a device under any free name. That is the price of letting the MDM
decide identity, and the reason the window is short.

**The agent certificate** says only "this caller may enrol a device while enrolment is open". Its CN is listed in RASENMAEHER's ``RM_MDM_AGENT_CNS``. It deliberately is **not** a
kraftwerk product CN: a product CN skips role checks, can have any request signed whatever its
subject, and cannot be revoked at the edge, which is far more than this needs. The CN is also
reserved as a callsign, so nobody can be issued a certificate that impersonates the agent.

What any MDM has to be able to do
=================================

Nothing in the enrolment path is specific to a product. The responder speaks RFC 8894 and knows
nothing about any MDM: there is not one product name in the request path. So the question "will
this MDM work" has three answers and no more.

1. **Point a custom SCEP authority at** ``https://<domain>/scep`` **with the deployment's
   challenge.** Most MDMs fetch ``GetCACert`` when the authority is saved, so a wrong URL fails at
   once.

2. **Name the device in the common name** with a per-device value it knows when the device
   enrols. Every MDM words its variables differently.

3. **Ask for an RSA key of 2048 bits or more.** We advertise ``POSTPKIOperation SHA-256 AES
   SCEPStandard`` and accept ``PKCSReq`` only. Elliptic curve keys cannot do the key transport SCEP
   defines, so a profile asking for one is refused with ``badAlg`` before anything is issued.

Pushing applications and device policy is a separate question and it is **not** portable: that
needs the MDM's own API, so it needs a driver. ``mdm-apply --mdm manual`` prints what to configure
by hand for an MDM we have no driver for, which is what "works with any MDM" honestly means.

The name the MDM gives a device
===============================

The MDM decides who a device is. The common name of its request becomes its callsign, in Deploy
App and in every product::

    CN=R58N12ABCDE               the callsign, and the user's identity from then on

The name has to be 3-30 letters A-Z or digits, the rule people's callsigns follow, because every
product takes it as a user name. A name somebody already has is refused, unless it is the same
device asking again with the same key. Other subject attributes are left to the MDM, and the
signer copies the subject into the certificate as it is.

Pick a value the MDM knows the moment a device enrols, so nobody names hosts by hand. One MDM's way
of writing it, as an example of the shape rather than as the syntax to copy::

    CN=$FLEET_VAR_HOST_HARDWARE_SERIAL

Check that your MDM actually has the value for your kind of enrolment before relying on it: a
personally owned phone may not report its serial number.

A subject that does not resolve is the failure to expect, and it is silent: the MDM sends no
request at all, so nothing reaches our logs and only the MDM can say why. ``rmscep selftest`` exists
to tell that apart from a broken responder.

What a device gets
==================

What to install is a property of the deployment, not of this service, so it arrives as a document
rather than as code. ``rmscep mdm-apply`` reads it and states it to the MDM: the applications,
their managed configuration, the device policy and a launcher link. There is a test that fails if
any product's package name appears in this repository's source.

Two halves make the browser present the certificate, and both are needed. The device policy's key
selection rules decide **which** key an application may use, without which a certificate installed
by the MDM belongs to the installing app and nothing else can see it. The browser's own
``AutoSelectCertificateForUrls`` decides whether it **sends** one; with no matching entry it
silently declines, which the proxy answers exactly as it answers a missing certificate.

The order that works
====================

Three facts about managed Android pull against each other. Each was learned by getting it wrong.

1. **Applications install at enrolment and at no other time.** The group must carry them before a
   device joins. Arming afterwards does nothing.
2. **A profile is delivered when the profile changes, not when a device arrives.** One uploaded
   before a device joined is never sent to it, so a first enrolment needs one forced re-upload.
3. **A policy rewritten while applications are installing stops them installing.** It never settles
   long enough for the store to finish.

So: apply the template before any device joins, open enrolment, enrol, and **leave the devices
alone** until the applications have arrived. With a name the MDM knows at enrolment, the first
certificate request already succeeds and nothing is left to do per device. A subject built from a
field somebody fills in by hand after enrolment brings the old trap back: the first request goes
out with an empty name and is refused, and the device gets a certificate only when the profile is
sent again.

Operating it
============

.. code-block:: bash

    rmscep init-ra                 # the RA identity, once, before any worker starts
    rmscep obtain-cert             # the client identity, renewed when it is running out
    rmscep mdm-apply               # state what devices need; --force-policy after one joins
    rmscep mdm-apply --dry-run     # validate the document without touching the MDM
    rmscep mdm-apply --mdm manual  # print what to configure by hand, for an MDM with no driver
    rmscep selftest CALLSIGN       # enrol as a device would, to prove the responder on its own
    rmscep healthcheck             # RA identity, CA chain, and the client certificate's expiry

``selftest`` creates a user under the name it is given, so use a throwaway name and remove the
user afterwards.
It is the only thing that separates "the responder is wrong" from "the MDM never asked", which from
the outside look identical and are answered in completely different places.

Failure, and how it is answered
===============================

A refusal and an outage are different answers, and telling them apart matters more than it sounds.

A **refusal** is final. Enrolment closed, name taken, or not a name a callsign may be: the device
gains nothing by asking again, so it gets a signed failure, and the operator opens enrolment or
changes the name the MDM gives it.

An **outage** is not a verdict on the device. RASENMAEHER restarting, or the front proxy rejecting
our client certificate while the revocation responder has not yet heard of it, are transient. Those
answer HTTP 503, because a signed failure is final to a SCEP client and would spend the enrolment
over a few minutes of warm-up. Redirects count as outages too: a redirect can only come from the
proxy in front, never from RASENMAEHER itself.

Anything malformed is refused rather than raised. The request is attacker-controlled bytes on a
public endpoint, and an uncaught exception there is a 500 with a traceback.

Known gaps
==========

**The challenge is the gate while the window is open.** Any enrolled device, and anyone who can
read the MDM's configuration, holds it, and with it can enrol a device under any free name until
the window closes. Keep windows short and check the device list after each one.

**A reset device cannot take its name back.** Its new key does not match the certificate the name
already has, and removing that user spends the name for good. An MDM that names devices by serial
number therefore needs a different name for a reset phone.

**Per-user product data is not delivered.** Applications install but come up unconfigured. The
declaration that would carry it is a later phase.

**Applications and policy are not portable.** The enrolment half works with any MDM that speaks
SCEP; stating what to install needs that MDM's API. The device policy this deployment ships is
Android Management API, so it carries to any Android EMM built on that and to nothing else, and
none of it carries to iOS. A second MDM needs either a driver or an operator following
``mdm-apply --mdm manual``.

**Nothing watches.** Container logs go to the host's syslog with no aggregation, so a burst of
refusals, which is what enumeration looks like, is visible only to someone reading a log on the box.
