#####################################################
# GA17 Privacy Enhancing Technologies -- Assessment

# A protocol for smart meter private billing and aggregation.
# (WARNING: THIS IS NOT PRODUCTION CODE -- DO NOT USE)
#
# Read the following code, and answer the questions below.

from petlib.ec import EcGroup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify
from petlib.pack import encode, decode
from petlib.cipher import Cipher

from random import randint, getrandbits
from binascii import hexlify
import os

# Define key derivation for authorities
def authority_key(G):
	o = G.order()
	x = o.random()
	g = G.generator()
	return (G, o, x, x*g)

# This is the code that a smart meter runs to certify the authenticity and
# integrity of the meter readings and facilitate bill verification and private
# real-time aggregation. The readings and meter_sign_key are private, and 
# G, tariffs, authority_keys are public. The output is a set of encrypted
# shares provided to aggregation authorities, as well as the bill and a proof
# it is correct.
##
# The meter readings is an array of energy consumed over time.
# The tariffs is an array of how much an energy unit costs at a time.
def meter_encode(G, readings, tariffs, authority_keys, meter_sign_key):
	assert all(0<= r <= 100 for r in readings)
	g = G.generator()

	# Commit to the readings
	# (By the hardness of the discreet log problem this is safe.)
	commit_readings = [r*g for r in readings]

	# Secret share the readings to each authority
	authority_shares = [[] for _ in authority_keys]

	for r in readings:
		total = 0
		for a in range(len(authority_keys) - 1):
			share = randint(0, 100)
			total -= share
			authority_shares[a].append(share)

		final_share = total + r
		authority_shares[-1].append(final_share)

		# Quick test -- that the secret sharing works
		assert (sum(v[-1] for v in authority_shares) == r)

	encrypted_authority_shares = []

	# Sign & encrypt the meter readings
	for (shares, akey) in zip(authority_shares, authority_keys):
		serialize = encode(shares)
		signature = do_ecdsa_sign(G, meter_sign_key, serialize)

		# Derive a shared key
		aes_key = hexlify((meter_sign_key*akey).export())

		aes = Cipher("AES-128-CTR")
		iv = aes_key[16:32]
		enc = aes.enc(aes_key[:16], iv)

		ciphertext = enc.update(serialize)
		ciphertext += enc.finalize()

		encrypted_authority_shares += [(meter_sign_key, commit_readings, ciphertext, signature)]

	# Prove total bill
	bill = sum(r*t for r,t in zip(readings, tariffs))
	return (commit_readings, bill), encrypted_authority_shares

# A function that allows for universal verification of the bill. All its parameters
# are assumed to be public.
def verify_bill(G, tariffs, commit_readings, bill):
	g = G.generator()
	return bill*g == sum([t*c for c,t in zip(commit_readings, tariffs)], G.infinite())


# The code ran by an authority to enable real-time aggregation of many readings using
# secret sharing. G, weights, encrypted_authority_shares are public, and dec_key is
# secret to each authority.
def authority_aggregation(G, weights, encrypted_authority_shares, dec_key):
	total_result = 0

	# Ignore malformed shares
	try:
		for ea_share in encrypted_authority_shares:
			# Derive shared key
			(meter_sign_key, commit_readings, ciphertext, signature) = ea_share
			shared_key = meter_sign_key*(dec_key*G.generator())

			# Decrypt and Check the authenticity of the readings
			aes_key = hexlify(shared_key.export())
			aes = Cipher("AES-128-CTR")
			iv = aes_key[16:32]
			dec = aes.dec(aes_key[:16], iv)

			plaintext = dec.update(ciphertext)
			plaintext += dec.finalize()

			shares = decode(plaintext)
			assert do_ecdsa_verify(G, meter_sign_key*G.generator(), signature, plaintext)

			total_result += sum(s*w for s,w in zip(shares, weights))

	finally:
		return total_result

# Tests

# Test key derivation
def test_auth_key():
	G = EcGroup()
	A1 = authority_key(G)

# Test outputs from the meter including bill verification and aggregation
def test_meter():
	G = EcGroup()

	As = [authority_key(G) for _ in range(3)]
	As_pub = [a[-1] for a in As]

	sig_key = G.order().random()
	ver_key = sig_key * G.generator()
	(commit_readings, bill), encrypted_authority_shares = meter_encode(G, [0, 10, 5, 0, 20], [2, 2, 5, 5, 2], As_pub, sig_key)

	assert verify_bill(G, [2, 2, 5, 5, 2], commit_readings, bill)

	total_share = 0
	for share, key in zip(encrypted_authority_shares, As):
		dec_key = key[-2]
		total_share += authority_aggregation(G, [1, 2, 0, 0, 0], [share], dec_key)

	assert total_share == 1*0 + 10*2

# Test aggregation of meter readings across multiple meters for the same time.
def test_aggregation():
	G = EcGroup()

	As = [authority_key(G) for _ in range(3)]
	As_pub = [a[-1] for a in As]

	readings = [0, 10, 5, 0, 20]
	tariffs = [2, 2, 5, 5, 2]

	meter_shares = []

	for m in range(3):
		sig_key = G.order().random()
		ver_key = sig_key * G.generator()
		(commit_readings, bill), encrypted_authority_shares = meter_encode(G, readings, tariffs, As_pub, sig_key)
		meter_shares += [encrypted_authority_shares]

	total_share = 0
	for a, key in enumerate(As):
		dec_key = key[-2]
		all_shares = [s[a] for s in meter_shares]

		total_share += authority_aggregation(G, [0, 1, 0, 0, 0], all_shares, dec_key)

	assert total_share == 10 * 3

# -------- ONLY SUBMIT SECTION BELOW ---------
# 
# QUESTIONS & ANSWERS

""" Reviewer (Student): TODO: YOUR NAME HERE! """

# Question Q1: Describe what this smart metering privacy system tries to achieve, and 
# what techniques it is using from the course? Under what assumptions on the meters
# and authorities can an ideal system using those techniques guarantee 
# integrity and privacy? [5 Marks]

""" his smart metering privacy system aims to remotely process smart meter readings of 
user's devices in an efficient way whilst preserving the user’s privacy. 
The authorities are able to have confidential access of how electricity 
is consumed and aggregates statistics without revealing any personal 
information about the users'. The system employs a secret-sharing technique 
to process the meter readings in a privacy-preserving fashion to protect 
the consumption information from being leaked. The protocol also implements 
a signature scheme to sign and encrypt the meter readings.  Privacy is 
guaranteed that if one of the authorities (e.g. G) is properly implemented 
in the protocol, the meter readings cannot disclose any personal information 
when processing authorized queries. Integrity is guaranteed under the assumption 
that the authorities comply with the protocol and, that they are honest and transparent 
in the way they operate the system. """

# Question Q2: Perform a code review, and identify potential flaws in the implementation
# of this privacy system. Describe the impact of each flaw. When a flaw is identified indicate 
# a possible fix for the flaw.
# 
# Present your findings as a list below by line numbers (not inline with the code.) 
# Feel free to use small code smippets to illustrate your answers.	[10 marks]

""" Your answer here 

(Example:

Lines X-Y: Description & impact of the flaw ... 
Fix: Description of the fix ...

Lines X-Y: Description & impact of the flaw ...
Fix: Description of the fix ...

Lines X-Y: Description & impact of the flaw ...
Fix: Description of the fix ...

)

"""

# Question Q3: In what ways would you improve the testing regime to catch the flaws you 
# identified above. Illustrate how different tests could have been used to catch specific 
# flaws you identified. [5 Marks]

""" Your answer here """
