#import random #find a csprng to replace with
import secrets

from tinyec import registry

def generate_private_key():
    """
    input:
        none

    output:
        privet_key: an int that uses 256 bits 
    """
    private_key = secrets.randbits(256)

    return private_key

#=============================================================================
#=============================================================================

def generate_pulic_key(private_key):
    """
    input:

    output:
    """
    return null 

def ecdh(private_key,public_key,other_person_pubic_key):
    """
    input:
    output:
    """
    return null
