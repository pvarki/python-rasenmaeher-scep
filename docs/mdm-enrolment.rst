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
product's package names. It unwraps the request and asks RASENMAEHER to complete an enrolment an
admin already planned.

**RASENMAEHER** owns the decision. It is the certificate authority, it holds the roster, and it is
the only component that can say yes.

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

Four things gate an enrolment, and it is worth being precise about which of them are real.

**The SCEP challenge is not a secret.** It sits in the MDM's configuration and travels in every
device's request. It keeps noise off the endpoint and nothing more. Any design that relies on it
being confidential is wrong.

**The agent certificate** says only "this caller may complete a device enrolment an admin already
planned". Its CN is listed in RASENMAEHER's ``RM_MDM_AGENT_CNS``. It deliberately is **not** a
kraftwerk product CN: a product CN skips role checks, can have any request signed whatever its
subject, and cannot be revoked at the edge, which is far more than this needs. The CN is also
reserved as a callsign, so nobody can be issued a certificate that impersonates the agent.

**The planned callsign** is the roster. An admin plans it ahead of time; the agent can only
complete what was planned, never create one.

**The per-enrolment code** is what binds a device to its callsign. This is the gate that matters,
because the endpoint is public and the callsign is a short human-chosen string that an attacker can
guess. RASENMAEHER already generates a random code on every planned row, and the MDM carries it
into the request's subject alongside the callsign.

The subject the MDM must produce
================================

The MDM has exactly one per-host string an operator can write. Put ``<callsign>@<code>`` in it, and
render it twice in the certificate template::

    CN=$FLEET_VAR_HOST_END_USER_IDP_USERNAME_LOCAL_PART   →  OTTER1
    OU=$FLEET_VAR_HOST_END_USER_IDP_USERNAME              →  OTTER1@7F3A9C2B

The common name stays the bare callsign, so the issued certificate and the user's identity are
unchanged. RASENMAEHER searches every subject attribute **except** the common name for the code,
so which attribute the MDM renders it into is the MDM's business. The common name is excluded on
purpose: accepting it there would let a caller who guessed the callsign satisfy the check with it.

A caller who guesses ``OTTER1`` has no code to put anywhere, and is refused before anything is
claimed, so guessing cannot spend a callsign either.

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

So, per device: apply the template once, plan the callsign, enrol, **leave it alone** until the
applications have arrived, then set the per-host field, then force the policy. Between enrolling
and setting the field the device will ask for a certificate with an empty subject and be refused.
That is harmless: the refusal happens before RASENMAEHER is asked, so no callsign is spent.

A device that has already enrolled cannot be rescued by repeating any of this. Give it a fresh
callsign and enrol it again, because the one it holds is spent and its new key will not match the
certificate that callsign already has.

Operating it
============

.. code-block:: bash

    rmscep init-ra                 # the RA identity, once, before any worker starts
    rmscep obtain-cert             # the client identity, renewed when it is running out
    rmscep mdm-apply               # state what devices need; --force-policy after one joins
    rmscep mdm-apply --dry-run     # validate the document without touching the MDM
    rmscep healthcheck             # RA identity, CA chain, and the client certificate's expiry

Failure, and how it is answered
===============================

A refusal and an outage are different answers, and telling them apart matters more than it sounds.

A **refusal** is final. Not planned, already taken, wrong code: the device gains nothing by asking
again, so it gets a signed failure and the operator plans another callsign.

An **outage** is not a verdict on the device. RASENMAEHER restarting, or the front proxy rejecting
our client certificate while the revocation responder has not yet heard of it, are transient. Those
answer HTTP 503, because a signed failure is final to a SCEP client and would spend the enrolment
over a few minutes of warm-up. Redirects count as outages too: a redirect can only come from the
proxy in front, never from RASENMAEHER itself.

Anything malformed is refused rather than raised. The request is attacker-controlled bytes on a
public endpoint, and an uncaught exception there is a 500 with a traceback.

Known gaps
==========

**Guessing is not bounded.** The code is checked, not consumed, so wrong guesses are free and
unlimited. Eight characters is ample against one attacker chasing one callsign, but an attacker who
will take any of a few hundred pending rows, from many addresses, is inside a couple of months. The
fix is a wrong-attempt counter on the row rather than a longer code: a bound per row makes length
irrelevant. Rotating a code costs no callsign, so recovery is cheap.

**The code lands in the issued certificate.** The signer copies the request's subject verbatim, so
the certificate carries ``OU=<callsign>@<code>`` for its lifetime. It is inert by then, but it is a
spent secret in a durable artefact. Removing it means letting the CA name the certificate rather
than accepting the request's subject.

**Per-user product data is not delivered.** Applications install but come up unconfigured. The
declaration that would carry it is a later phase.

**Nothing watches.** Container logs go to the host's syslog with no aggregation, so a burst of
refusals, which is what enumeration looks like, is visible only to someone reading a log on the box.
