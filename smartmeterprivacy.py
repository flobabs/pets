#####################################################
# GA17 Privacy Enhancing Technologies -- Assessment

# QUESTIONS & ANSWERS

""" Reviewer (Student): BABATUNDE MOHAMMED OLOGBURO! """

# Question Q1: Describe what this smart metering privacy system tries to achieve, and 
# what techniques it is using from the course? Under what assumptions on the meters
# and authorities can an ideal system using those techniques guarantee 
# integrity and privacy? [5 Marks]

""" This smart metering privacy system aims to remotely process smart meter readings of 
user's devices in an efficient way whilst preserving the user’s privacy. 
The authorities are able to have confidential access of how electricity 
is consumed and aggregates statistics without revealing any personal 
information about the users. The system employs a secret-sharing technique 
to process the meter readings in a privacy-preserving fashion to protect 
the consumption information from being leaked. The protocol also implements 
a signature scheme to sign and encrypt the meter readings. It also uses asymmetric key 
encryption to encrypt and decrypt the data with the private and public key, 
and zero knowledge proof is used to prove the integrity of the statements of the secrets 
without leaking any information about the secret. 
Privacy is guaranteed that if one of the authorities (e.g. G) is 
properly implemented in the protocol, the meter readings cannot disclose any personal 
information when processing authorized queries. 
Integrity is guaranteed under the assumption that the plaintexts are signed so when 
the authorities decrypt it there is a signature that can validate the claim. 
Also, under the assumption that the authorities follow and comply with the protocol, 
and that they are honest and transparent in the way they operate the system.
"""

# Question Q2: Perform a code review, and identify potential flaws in the implementation
# of this privacy system. Describe the impact of each flaw. When a flaw is identified indicate 
# a possible fix for the flaw.
# 
# Present your findings as a list below by line numbers (not inline with the code.) 
# Feel free to use small code smippets to illustrate your answers.	[10 marks]

""" Line :

(Example:
Line 75: This line exceeded the maximum characters a line should have with 
Fix: 	encrypted_authority_shares \
	+= [(meter_sign_key, commit_readings, ciphertext, signature)]
Line 35: This line has bad whitespace
Fix: inserting a single space after 0 is more appropriate: assert all(0 <= r <= 100 for r in readings)

Line 78: Missing spacing 
Fix: inserting a single whitespace after the comma: bill = sum(r*t for r, t in zip(readings, tariffs))

Line 85: The line has bad whitespace
Fix: inserting a single whitespace after the comma: return bill*g == sum([t*c for c, t in zip(commit_readings, tariffs)], G.infinite())

Line 113: the line has bad whitespace
Fix: Inserting a single whitespace after the comma: total_result += sum(s*w for s, w in zip(shares, weights))

Line 134: This line has exceeded the maximum characters a line should have with 122 characters. 
The maximum characters a line should have is 79 characters.
Fix: IT can be fixed by adding backlashes after the commas: (commit_readings, bill), \
                                           		    encrypted_authority_shares = meter_encode(G, [0, 10, 5, 0, 20], \
					                    [2, 2, 5, 5, 2], As_pub, sig_key)

Line 160: This line has exceeded the maximum characters a line should have with 105 characters.
The maximum characters a line should have is 79 characters.
Fix it can be fixed by adding backlashes after the commas: (commit_readings, bill), \
      						           encrypted_authority_shares = meter_encode(G, readings, tariffs, As_pub, sig_key)
Line 170: Unnessesary spacing
Fix: Removing the unwanted spacing in the multiplication: assert total_share == 10*3

Line 14: getrandbits was imported in the code but wasn't used at all in the protocol.
Fix: eliminate the getrandbits 

Line 75: This statement meter_sign_key is being discolsed to the public reveals the private key, the private key shouldn't 
be publicly published.
fix: The private key should be removed.
line 95: If an error occurs within this try block, there is no statement that  handles or catches the error/exceptions. 
Therefore, it will only generate the total result.
Fix: adding an except block within the code will handle exceptions produced by its statement. 
The except block will print the executions, stop the program, and can perform error recovery to notify the coder about the error. 
For example adding except ValueError:
			print("Invalid Input")
Line 69: The iv used is not random. That is, it is predictable and the ciphertexts remains the same 
when encrypted again which will leak information.
Fix: instead of using an iv, a unique nonce can be used.

Line 35: There are no check if the readings are on the lists. 
Fix: There should be a return statement that raises an AssertionError whenever there is an exception.
For example adding another line with: if not:(0<= r <= 100 for r in readings)	
					  raise AssertionError(Message)
Line 48: The randint() is not cyptographically random as it is deterministic, therefore
it is not secure as an adversary can predict
Fix: use os.urandom as it is crytographically secure.

"""

# Question Q3: In what ways would you improve the testing regime to catch the flaws you 
# identified above. Illustrate how different tests could have been used to catch specific 
# flaws you identified. [5 Marks]


""" I believe the testing regime should be more exhaustive to cover more of the cases.
It should cover any possible cases for the inputs that are not checked and give a correct 
or wrong input to the tests depending on how the system responds. There's no negative 
testing, that is, if fails to handle invalid input or when there is an error in the system.
The test should cover functions with different inputs in the tests. 
example: with weights = [0,0,0,0], "a", [1,2,3,4,5,6,7,9,10......50] and, types, decimals, and every 
other possible number. This action should be done for the readings, tariffs and every 
possible case. 



"""
