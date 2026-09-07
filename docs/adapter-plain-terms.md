# The LIJOX adapter, in plain terms

Source copy for the eventual website (S41, DP-approved framing; custody
paragraph made exact per DP's question 2026-08-29).

## What it is
One program that runs beside an existing Lightning node. It does not
replace the node, modify its software, or touch its wallet, seed, or
history. It talks to the node through the node's own control interface,
using a permission key the operator creates. The key allows a fixed list
of actions and nothing else.

## What it does for LiJ wallets
Four jobs. It announces "this LSP exists" to the registry — signed with
the node's own key, so nobody can impersonate it. It opens a channel to a
new wallet the moment that wallet receives its first payment. It builds
payment routes when wallets ask. And it holds locked payments for wallets
that are offline until they return.

## Does it hold the money? The exact answer.
It holds the payment itself — but in a form it cannot take. When money
arrives for a wallet that is offline, the sats sit inside a channel under
a lock. Only the recipient's secret opens that lock, and that secret
never leaves the recipient's phone. The adapter can do exactly two
things with a locked payment: complete the delivery when the wallet comes
back, or cancel so the money returns to the sender. Taking the money is
not one of its options — not by policy, by math. The sender's sats are
committed while the lock stands (they cannot be spent elsewhere), and
the lock only opens toward the recipient.

## What it touches on the node — the complete list
It reads channel, peer, and balance information. It can open new
channels — that moves some of the node's on-chain sats into channels,
which is the LSP's job and the only spending it does. It creates and
settles the special invoices behind offline receive. And it registers as
a forward interceptor: for payments passing through the node addressed
to LiJ wallets, the node asks the adapter for a decision before
completing them; all other traffic passes through untouched.

What its permission key forbids: sending on-chain coins away, closing
channels, paying invoices, reading the seed. The node's existing
channels keep operating exactly as they did before.

## Where it runs
On the node's own computer, as an added background service, so the LSP
lives and dies with its own node and nothing else.
