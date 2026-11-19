# glyph

People talk by glyph ID. The ID is a key you share by hand. Nobody else can find you.

A mailbox on the owner's LAN holds sealed letters while an app is closed. The mailbox never reads them.

## Identity

A glyph ID is static. It is `glyph:` plus the public half of a key generated on this machine. It is unguessable. It is not registered anywhere.

Share the whole ID. A short prefix is not an address.

The ID changes only inside a conversation that already exists. This app seals one message to that friend: the next ID is this, and the next key signs that message. Their app keeps the transcript and follows the new ID after they accept it. Anyone who was not in that conversation still cannot find either ID. If that message is never sent, the new ID is a new person.

## Privacy

Users are anonymous except to someone who already has their glyph ID.

This program does not announce itself on the LAN, keep a peer directory, look people up by name, or publish who is online. Knowing an ID is the only way to address someone.

## Messages

A message is signed by the sender and sealed to the recipient's glyph ID. The mailbox stores ciphertext. The connection to the mailbox is TLS, pinned to that mailbox's key.

Each message carries:

- a counter, one sequence per sender in that conversation
- a send time, for display

The app shows messages in counter order. It holds a letter until the next counter arrives. The send time is not the order. Clocks disagree, and a sender can write any time.

## Conversations

A conversation is local. It is stored under the friend's current glyph ID. A display name is a private label on this machine. It is never an address and never a way to search.

Opening a chat means pasting a glyph ID you were given. Sending seals to that ID and hands the letter to the mailbox.

## Mailbox

The mailbox is a separate program, [glyph-mailbox](https://github.com/01wrx/glyph-mailbox). It is a LAN peer of its owner.

- It listens on the LAN only, and only for a private, loopback, or link-local source.
- It accepts the owner, and friends the owner has introduced by glyph ID. The owner can remove a friend.
- It stores opaque letters and returns them in pages when that recipient's app asks.
- It does not read mail, enroll strangers, or publish its address.

The owner's app reads the mailbox key from the mailbox directory. A friend on that same LAN uses the same box for both directions, and is given the address together with the mailbox public key (`box-pub`, or `GLYPH_MAILBOX` and `GLYPH_MAILBOX_KEY`). A friend who is not on that LAN cannot reach the box.

Either person can close glyph. Letters wait on the mailbox until an app on that LAN picks them up.

## This program

glyph is the app people run:

- one key file
- local transcripts
- a window with your ID, chats, a composer, and the mailbox address

Seal, then hand the blob to the mailbox. Pull blobs addressed to you and open them.

## Not in this program

No live LAN messenger, no DHT, no public-IP lookup, no machine attestation, and no accounts. Those made people findable or tied an ID to a particular computer. They are not part of this design.
