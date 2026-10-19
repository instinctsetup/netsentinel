# The math inside netsentinel, in plain words

## 1. Internet checksum (RFC 1071)

Used by IPv4. Treat the header as 16-bit numbers, add them up, and every time the sum overflows 16 bits, feed the overflow back in ("end-around carry"). Flip all the bits at the end - that is the checksum. The receiver adds up the header *including* the checksum; a valid header sums to all-ones (zero after flipping). One flipped bit anywhere changes the sum, so corruption is caught.

Why it is weak but loved: it is three lines of code and catches every single-bit error. It is not cryptographic - deliberately changing two bits that cancel out defeats it.

## 2. Shannon entropy of a DNS label

    H = - sum over characters c:  p(c) * log2(p(c))

Entropy measures "surprise per character". English hostnames reuse a small set of letters with strong patterns, so `www` or `mailserver` score roughly 1.5-2.8 bits/char. A base32 tunnelling label like `mfrggzdfmztwq2lk` uses ~32 symbols almost uniformly, scoring 4+ bits/char. Combined with label length (real names are short; tunnels max out the 63-char label limit), entropy separates tunneled queries from real ones with a rule you can explain on a whiteboard.

## 3. TCP sequence arithmetic

Every byte of a TCP stream has a number. SYN consumes one number; FIN consumes one number. `ACK = next byte I expect`. That is why our VirtualStack adds 1 after SYN and FIN but adds `len(payload)` after data - the handshake and teardown are visible in the arithmetic itself.

## 4. Logistic regression (the ML add-on)

Model: `p = sigmoid(w . x + b)` where `sigmoid(z) = 1 / (1 + e^-z)` squashes any number into (0,1) - read it as "probability this window is an attack".

Loss (cross-entropy): for one example, `L = -y*log(p) - (1-y)*log(1-p)`. If the truth is "attack" (y=1) and the model says p=0.99, the loss is tiny (0.01); if it says p=0.01 the loss is huge (4.6). It punishes confident wrongness.

Gradient: with the sigmoid + cross-entropy pair, the derivative collapses beautifully to `dL/dw = x * (p - y)` - error times input. Training subtracts a small step of that, repeatedly. `detectors.WindowClassifier.fit` is exactly this loop over feature vectors of real generated windows.

Features (10): SYN count, SYN-ACK count, RST count, DNS count, HTTP count, UDP count, max distinct ports from one source, max SYNs to one target, average DNS label length, average label entropy. All z-scored with training-set mean/std before training so no feature dominates by scale.

## 5. ROC AUC (in metrics.py)

The probability that a randomly chosen attack window scores higher than a randomly chosen benign window. Computed by direct comparison of all pairs (the rank formulation), not by sklearn. 1.0 = perfect separation, 0.5 = coin flip.
