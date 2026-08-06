# PUFToken

Proof of concept of a PUF-based electronic payment protocol.

The project implements the spending phase of the protocol using an architecture
inspired by the GK-PHEMAP proof of concept.

## Initial scope

The first version includes:

- Device;
- Payment System;
- simulated initialization setup;
- simulated PUF function;
- simulated cryptographic primitives;
- one spending transaction.

Bank and Trusted Authority are not active actors during the spending phase and
are therefore simulated by the setup module.