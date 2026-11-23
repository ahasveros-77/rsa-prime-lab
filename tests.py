from src.rsa_math import *
k=generate_key_data(47,71,79)
x=text_to_decimal_blocks('HARI INI',3337)
assert x['ascii_codes']==['72','65','82','73','32','73','78','73']
assert x['digit_string']=='7265827332737873'
assert x['display_blocks']==['726','582','733','273','787','003']
assert x['values']==[726,582,733,273,787,3]
c=encrypt_blocks(x['values'],79,3337)
assert c==[215,776,1743,933,1731,158]
text,_,_=decimal_blocks_to_text(decrypt_blocks(c,1019,3337),x['lengths'])
assert text=='HARI INI'
print('All PPT-method tests passed')
