# Pitch script

Narration for the animated presentation (`animations/pitch.html`). Each section is one press of **→**: start speaking as the animation plays, press → when you finish the line. About 3½ minutes at a normal pace, including the 38-second dashboard footage at the end.

---

### 1 · Title
*(Quantum-Safe Gateway; the orange lock turns teal)*

> "Hi, we're [team name]. This is the Quantum-Safe Gateway: a way to make old systems safe from quantum computers, without rewriting them."

**→**

### 2 · Harvest now
*(Records travel to the bank; the eavesdropper records them)*

> "Every day, banks send customer records across networks, encrypted with RSA. An attacker can't read that traffic today. But they can record it and keep it."

**→**

### 3 · Decrypt later
*(The year counts to 2036; the quantum computer opens the locks; names appear)*

> "Years from now, a large enough quantum computer will break RSA, and everything recorded today gets unlocked. That's 'harvest now, decrypt later'. Anything that has to stay secret for ten years or more is already at risk."

**→**

### 4 · The legacy problem
*(An RSA lock on the legacy server)*

> "The obvious fix is to upgrade every system to quantum-safe encryption. But these are old systems. Rewriting them is slow, expensive and risky."

**→**

### 5 · The gateway
*(The gateway slides in; the link turns teal; the quantum computer fails)*

> "So instead, we put a gateway in front. Clients connect to it using hybrid TLS: classical X25519 plus ML-KEM, the new NIST post-quantum standard. The old server doesn't change at all. And this time, when the quantum computer goes through the recordings, they stay locked."

**→**

### 6 · Strict mode
*(A client offering only the old lock is refused)*

> "In strict mode, anything that only offers the old encryption is turned away at the door."

**→**

### 7 · Data at rest
*(The records file)*

> "It's not just data in transit. Data sitting on disk is a target too. Copy this file, and you have everything."

**→**

### 8 · Step 1
*(An AES key scrambles the file)*

> "So we encrypt it with a fresh AES-256 key…"

**→**

### 9 · Step 2
*(The key goes into the ML-KEM envelope)*

> "…and then lock that key itself with ML-KEM. Only our private key can open it, and changing even one byte makes it refuse to unlock."

**→**

### 10 · Downgrade setup
*(The client offers both locks)*

> "Now, attackers know this. So instead of breaking the new lock, they try to get rid of it. A client normally offers the quantum-safe option, with the old one as a fallback…"

**→**

### 11 · The attack
*(The attacker strikes out the quantum-safe line)*

> "…and an attacker in the middle quietly deletes the quantum-safe option, hoping the connection falls back to encryption they can break later. That's a downgrade attack."

**→**

### 12 · AI tripwire
*(History dots: green, green, green, orange; red banner)*

> "Our AI tripwire watches every handshake. This client has always offered the quantum-safe lock, and suddenly it doesn't. That's flagged instantly, and the gateway refuses the connection. The tripwire also uses an anomaly model to catch subtler things, like connection bursts or weakened ciphers."

**→**

### 13 · Audit log
*(Log lines with chained seals)*

> "Every connection is recorded in an audit log, and each line is sealed with ML-DSA, the post-quantum signature standard, chained to the line before it."

**→**

### 14 · Tampering
*(The attacker edits line 3)*

> "So if an attacker edits the log to cover their tracks, making their downgrade look like a normal connection…"

**→**

### 15 · Verification
*(The scan breaks at line 3)*

> "…verification catches it at exactly the line they changed. Edits, deletions and reordering are all detected."

**→**

### 16 · LinuxONE
*(The benchmark chart)*

> "We built and benchmarked all of this on IBM LinuxONE, the platform that runs much of the world's banking. Going quantum-safe adds about a third of a millisecond per connection, and throughput drops by only six percent."

**→**

### 17 · Summary
*(Checklist)*

> "So that's quantum-safe networking, encrypted data, an AI tripwire, and tamper-proof logs, all in front of a legacy server that stays exactly as it is."

**→**

### 18 · Here it is running
*(Laptop with a LIVE indicator)*

> "And this isn't just slides. Here's the real dashboard and detector, running on simulated bank traffic."

**→**

### 19 · Dashboard footage (38 s, plays by itself; the captions say each step)
*(Green dashboard → red banner → risk table → anomalies → TAMPERED)*

> "Everything's green: about nine in ten connections are quantum-safe, and the rest come from legacy machines, which the dashboard lists as needing an upgrade.
>
> Now an attacker strips the quantum-safe option from a client. The banner goes red instantly, and the risk table puts that client first, with a plain-English explanation.
>
> Next, subtler attacks that no fixed rule would catch. The AI model spots them, and you can see them jump above its threshold.
>
> Finally, the attacker edits the audit log to cover their tracks, and the ML-DSA seals flag it as tampered.
>
> Thank you."

---

## Notes for the presenter

- **Fill in the team name** in section 1.
- **Section 3, if a judge asks:** the live demo's "cracking" uses a deliberately tiny 64-bit RSA key, and quantum computers that can break real RSA don't exist yet. The animation says this on screen; don't claim more.
- **Sections 12 and 19:** the anomaly model catches bursts and weak ciphers on the detector's test traffic, but it currently over-flags real gateway traffic (it needs retraining on real gateway logs). If that hasn't been fixed when you record, cut the last sentence.
- **Section 16 numbers** come from `gateway/bench/benchmarks.md` (500 handshakes per mode on the team's LinuxONE VM, 3 CPUs, loopback): 0.70 ms classical vs 1.03 ms hybrid; throughput 2,371 → 2,224 MB/s.
- **Bridge to the live demo:** "That was the idea. Now let's see it actually running." Then run `./demo.sh`.
