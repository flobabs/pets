#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 02
#
# Basics of Mix networks and Traffic Analysis
#
# Run the tests through:
# $ py.test -v test_file_name.py

#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can 
#           be imported.

###########################
# Group Members: Killian Davitt, Babatunde Mohammed Ologburo
###########################


from collections import namedtuple
from hashlib import sha512
from struct import pack, unpack
from binascii import hexlify
from os import urandom

def aes_ctr_enc_dec(key, iv, input):
    """ A helper function that implements AES Counter (CTR) Mode encryption and decryption. 
    Expects a key (16 byte), and IV (16 bytes) and an input plaintext / ciphertext.

    If it is not obvious convince yourself that CTR encryption and decryption are in 
    fact the same operations.
    """
    
    aes = Cipher("AES-128-CTR") 

    enc = aes.enc(key, iv)
    output = enc.update(input)
    output += enc.finalize()

    return output

#####################################################
# TASK 2 -- Build a simple 1-hop mix client.
#
#


## This is the type of messages destined for the one-hop mix
OneHopMixMessage = namedtuple('OneHopMixMessage', ['ec_public_key', 
                                                   'hmac', 
                                                   'address', 
                                                   'message'])

from petlib.ec import EcGroup
from petlib.hmac import Hmac, secure_compare
from petlib.cipher import Cipher

def mix_server_one_hop(private_key, message_list):
    """ Implements the decoding for a simple one-hop mix. 

        Each message is decoded in turn:
        - A shared key is derived from the message public key and the mix private_key.
        - the hmac is checked against all encrypted parts of the message
        - the address and message are decrypted, decoded and returned

    """
    G = EcGroup()

    out_queue = []

    # Process all messages
    for msg in message_list:

        ## Check elements and lengths
        if not G.check_point(msg.ec_public_key) or \
               not len(msg.hmac) == 20 or \
               not len(msg.address) == 258 or \
               not len(msg.message) == 1002:
           raise Exception("Malformed input message")

        ## First get a shared key
        shared_element = private_key * msg.ec_public_key
        key_material = sha512(shared_element.export()).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        ## Check the HMAC
        h = Hmac(b"sha512", hmac_key)        
        h.update(msg.address)
        h.update(msg.message)
        expected_mac = h.digest()

        if not secure_compare(msg.hmac, expected_mac[:20]):
            raise Exception("HMAC check failure")

        ## Decrypt the address and the message
        iv = b"\x00"*16

        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)

        # Decode the address and message
        address_len, address_full = unpack("!H256s", address_plaintext)
        message_len, message_full = unpack("!H1000s", message_plaintext)

        output = (address_full[:address_len], message_full[:message_len])
        out_queue += [output]

    return sorted(out_queue)
        
        
        
def mix_client_one_hop(public_key, address, message):
    """
    Encode a message to travel through a single mix with a set public key. 
    The maximum size of the final address and the message are 256 bytes and 1000 bytes respectively.
    Returns an 'OneHopMixMessage' with four parts: a public key, an hmac (20 bytes),
    an address ciphertext (256 + 2 bytes) and a message ciphertext (1002 bytes). 
    """

    G = EcGroup()
    assert G.check_point(public_key)
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    # Encode the address and message
    # Use those as the payload for encryption
    address_plaintext = pack("!H256s", len(address), address)
    message_plaintext = pack("!H1000s", len(message), message)

    ## Generate a fresh public key
    private_key = G.order().random()
    client_public_key  = private_key * G.generator()

    #####

    shared_key = public_key.pt_mul(private_key)
    shared_key = shared_key.export()
    digest_of_key = sha512(shared_key).digest() 

    hmac_key = digest_of_key[:16]
    address_key = digest_of_key[16:32]
    message_key = digest_of_key[32:48]
    
    iv = b"\x00"*16
    
    message_cipher = aes_ctr_enc_dec(message_key, iv,
    message_plaintext)
    
    address_cipher = aes_ctr_enc_dec(address_key, iv,
    address_plaintext)

    
    h = Hmac(b"sha512", hmac_key)
    h.update(address_cipher)
    h.update(message_cipher)

    expected_mac = h.digest()[:20]

    
    return OneHopMixMessage(client_public_key, expected_mac, address_cipher, message_cipher)

    

#####################################################
# TASK 3 -- Build a n-hop mix client.
#           Mixes are in a fixed cascade.
#

from petlib.ec import Bn

# This is the type of messages destined for the n-hop mix
NHopMixMessage = namedtuple('NHopMixMessage', ['ec_public_key', 
                                                   'hmacs', 
                                                   'address', 
                                                   'message'])


def mix_server_n_hop(private_key, message_list, final=False):
    """ Decodes a NHopMixMessage message and outputs either messages destined
    to the next mix or a list of tuples (address, message) (if final=True) to be 
    sent to their final recipients.

    Broadly speaking the mix will process each message in turn: 
        - it derives a shared key (using its private_key), 
        - checks the first hmac,
        - decrypts all other parts,
        - either forwards or decodes the message. 
    """

    G = EcGroup()

    out_queue = []

    # Process all messages
    for msg in message_list:

        ## Check elements and lengths
        if not G.check_point(msg.ec_public_key) or \
               not isinstance(msg.hmacs, list) or \
               not len(msg.hmacs[0]) == 20 or \
               not len(msg.address) == 258 or \
               not len(msg.message) == 1002:
           raise Exception("Malformed input message")

        ## First get a shared key
        shared_element = private_key * msg.ec_public_key
       
        key_material = sha512(shared_element.export()).digest()
        
        
        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]
        
        # Extract a blinding factor for the public_key
        blinding_factor = Bn.from_binary(key_material[48:])
        new_ec_public_key = blinding_factor * msg.ec_public_key
        #### Key material changes every time...soo each successive
        #### node has key*r... 
        
        ## Check the HMAC
        h = Hmac(b"sha512", hmac_key)
        for other_mac in msg.hmacs[1:]:
            h.update(other_mac)
            

        h.update(msg.address)
        h.update(msg.message)

        expected_mac = h.digest()
                
        if not secure_compare(msg.hmacs[0], expected_mac[:20]):
            raise Exception("HMAC check failure")

        ## Decrypt the hmacs, address and the message
        aes = Cipher("AES-128-CTR") 

        # Decrypt hmacs
        new_hmacs = []
        for i, other_mac in enumerate(msg.hmacs[1:]):
            # Ensure the IV is different for each hmac
            iv = pack("H14s", i, b"\x00"*14)

            hmac_plaintext = aes_ctr_enc_dec(hmac_key, iv, other_mac)
            new_hmacs += [hmac_plaintext]

        # Decrypt address & message
        iv = b"\x00"*16
        
        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)

        if final:
            # Decode the address and message
            address_len, address_full = unpack("!H256s", address_plaintext)
            message_len, message_full = unpack("!H1000s", message_plaintext)

            out_msg = (address_full[:address_len], message_full[:message_len])
            out_queue += [out_msg]
        else:
            # Pass the new mix message to the next mix
            out_msg = NHopMixMessage(new_ec_public_key, new_hmacs, address_plaintext, message_plaintext)
            out_queue += [out_msg]

    return out_queue


def mix_client_n_hop(public_keys, address, message):
    """
    Encode a message to travel through a sequence of mixes with a sequence public keys. 
    The maximum size of the final address and the message are 256 bytes and 1000 bytes respectively.
    Returns an 'NHopMixMessage' with four parts: a public key, a list of hmacs (20 bytes each),
    an address ciphertext (256 + 2 bytes) and a message ciphertext (1002 bytes). 

    """
    G = EcGroup()
    # assert G.check_point(public_key)
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    # Encode the address and message
    # use those encoded values as the payload you encrypt!
    address_plaintext = pack("!H256s", len(address), address)
    message_plaintext = pack("!H1000s", len(message), message)

    ## Generate a fresh public key
    private_key = G.order().random()
    client_public_key  = private_key * G.generator()

    iv = b"\x00"*16

    # caluculate the blinding factor of all the
    # hops, can't be done during hmacs as it's in a different order.
    # 
    blind_factors = []
    shared_keys = []
    for i,k in enumerate(public_keys):
        if i == 0:
            blind_factors.append(1)
        else:

            pub_key = public_keys[i-1]

            # The shared key that the hop will use to calculate the factor
            shared_key = shared_keys[i-1]
            key_digest = sha512(shared_key).digest()
            # the blinding factor that they will use
            blinding_factor = Bn.from_binary(key_digest[48:])
            blind_factors.append(blinding_factor)

        shared_key = public_keys[i].pt_mul(private_key)
        for j, fac in enumerate(blind_factors[0:i+1]):
            shared_key = shared_key.pt_mul(blind_factors[j])
        shared_key = shared_key.export()
        shared_keys.append(shared_key)

    ## Reverse the key lists, since we will compute hmacs in reverse order
    shared_keys.reverse()
    public_keys.reverse()

    message_ciphers = []
    address_ciphers = []
    hmacs = []
    
    previous_hmac_key = None
    for i, pub in enumerate(public_keys):
        # Get shared key from precomputed list 
        shared_key = shared_keys[i]
        key_digest = sha512(shared_key).digest()
        address_key = key_digest[16:32]
        message_key = key_digest[32:48]
        hmac_key = key_digest[:16]
        ## 1. Encrypt The Message
        if i==0:
            message_cipher = aes_ctr_enc_dec(message_key, iv, message_plaintext)
            address_cipher = aes_ctr_enc_dec(address_key, iv,
                                     address_plaintext)
        else:
            message_cipher = aes_ctr_enc_dec(message_key, iv, message_ciphers[i-1])
            address_cipher = aes_ctr_enc_dec(address_key, iv,
                                             address_ciphers[i-1])
        message_ciphers.append(message_cipher)
        address_ciphers.append(address_cipher)

        
        ## 2. Encrypt the old HMACs
        for q, mac in enumerate(hmacs):
            iv = pack("H14s", len(hmacs)-q-1, b"\x00"*14)
            hmacs[q] = aes_ctr_enc_dec(hmac_key, iv, mac)

        previous_hmac_key = hmac_key

        ## 3. Compute the new HMAC
        h = Hmac(b"sha512", hmac_key)

        ## Iterate backwards through the previous hmacs
        for old_mac in hmacs[::-1]:
            h.update(old_mac)
        h.update(address_ciphers[i])
        h.update(message_ciphers[i])
        

        new_mac = h.digest()

        hmacs.append(new_mac[:20])
      
    # Hmacs were built in reverse order, put them back in order
    hmacs.reverse()

    return NHopMixMessage(client_public_key, hmacs, address_ciphers[len(address_ciphers)-1], message_ciphers[len(message_ciphers)-1])



#####################################################
# TASK 4 -- Statistical Disclosure Attack
#           Given a set of anonymized traces
#           the objective is to output an ordered list
#           of likely `friends` of a target user.

import random

def generate_trace(number_of_users, threshold_size, number_of_rounds, targets_friends):
    """ Generate a simulated trace of traffic. """
    target = 0
    others = range(1, number_of_users)
    all_users = range(number_of_users)

    trace = []
    ## Generate traces in which Alice (user 0) is not sending
    for _ in range(number_of_rounds // 2):
        senders = sorted(random.sample( others, threshold_size))
        receivers = sorted(random.sample( all_users, threshold_size))

        trace += [(senders, receivers)]

    ## Generate traces in which Alice (user 0) is sending
    for _ in range(number_of_rounds // 2):
        senders = sorted([0] + random.sample( others, threshold_size-1))
        # Alice sends to a friend
        friend = random.choice(targets_friends)
        receivers = sorted([friend] + random.sample( all_users, threshold_size-1))

        trace += [(senders, receivers)]

    random.shuffle(trace)
    return trace


from collections import Counter

def analyze_trace(trace, target_number_of_friends, target=0):
    """ 
    Given a trace of traffic, and a given number of friends, 
    return the list of receiver identifiers that are the most likely 
    friends of the target.
    """

    # Remove all traces that the target doesn't send in
    for t in trace:
        if target not in t[0]:
            trace.remove(t)

    c = Counter(trace[0][0])


    ## iterate traces, if a receiver received when target was sending,
    ## increment count
    for t in trace:
        for i in t[1]:
            c[i] += 1

    # Get most common friends and return
    q = (c.most_common(target_number_of_friends))
    q = [x[0] for x in q] 
    return q

## TASK Q1 (Question 1): The mix packet format you worked on uses AES-CTR with an IV set to all zeros. 
#                        Explain whether this is a security concern and justify your answer.

""" 

Since for every message sent to the mix, the client generates a new
private key. Since the symmetric shared key is derived from the
private key, every message will look different, so there is no need to
introduce a random IV.

The purpose of an initialisation vector is to prevent the exact same
message from encrypting to the same ciphertext, if it is encrypted on
two seperate occasions. but, if the  key is different every
time, the plaintexts will differ completely anyway, so there is no
need for an IV.

We can see on line 291 of this file that the client gets a random
private key each time. (This is okay as there is no need for the
client to authenticate itself to the servers.)

furthermore as long as there is a changing counter (which there is in counter mode), the
subsequent blocks of the cipher will not encrypt to the same value so
this is not an additional concern introduced by zero iv's.

"""



## TASK Q2 (Question 2): What assumptions does your implementation of the Statistical Disclosure Attack 
#                        makes about the distribution of traffic from non-target senders to receivers? Is
#                        the correctness of the result returned dependent on this background distribution?

"""The assumption is made that non-target senders, do not send data to
the targets friends. 

The attack is based on the fact that it is more likely that friends of
the target will appear as receivers in the same trace as the target is
sending. If, for most traces where the target sends, particular
receivers occur often, they are likely to be friends, so, if, in
traces where the target sends, the worst possibility is that other non
friends are found to be equally likely to be the friends of the
target.

It also makes the assumption that, every other sender is not sending a
message at the same time as the target. If, at every time the target
sends a message, every other sender also sends a message; then, this
attack would not work.

"""
