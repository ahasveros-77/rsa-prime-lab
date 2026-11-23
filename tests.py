from src.rsa_math import *
assert is_prime(47) and is_prime(71) and not is_prime(49)
k=generate_key_data(47,71,79)
assert (k['n'],k['phi'],k['d'])==(3337,3220,1019)
blocks=[726,582,733,273,787,3]
c=encrypt_blocks(blocks,k['e'],k['n'])
assert c==[215,776,1743,933,1731,158]
assert decrypt_blocks(c,k['d'],k['n'])==blocks
text='HARI INI'
b,l,_=text_to_blocks(text,k['n'])
assert blocks_to_text(decrypt_blocks(encrypt_blocks(b,k['e'],k['n']),k['d'],k['n']),l)==text
print('All RSA tests passed')
