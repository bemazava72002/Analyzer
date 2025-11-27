text = "Hello everybody"
#1  returns the string in upper case:

txt = "julio bemazava"

print(text.upper())

# 2 return the string in lower case
print(text.lower())

#3 Get the charactere from 2eme - 3eme output: el
print(text[1:3])
# Get the charactere from expected output: everbo

print(text[-9:-2])

# Expected output:elloev [1, 7[ output: loeve, output: everybo, out
#Expected output: elloever
print(text[1:9])

#Expected output eve
print(text[5:8])


#Expected output: lio bema
print(txt[2:10])

#Expected output: emaza

print(txt[-7:-2])

#Expected output: bemazav
print(txt[-8:-1])
print(txt[6:13])
#Expected output: io be
print(txt[3:8])
print(txt[-11:-6])

#Expected output: ['Hello','World']
print(txt.split(" "))
#Expected output: ['Hello' 'World']
print(text.split(" ")) 

#Expected output: ['Hello','World']
print(text.split(" "))
#Expected output: ['H', 'e']
print(str(text[0].split(" ") + text[1].split(" ")))
#Expected output: Helloeverybody
print(str(text.split(" ")[0] + text.split(" ")[1]))

#Expected output: Jelloeverybody

print(str(text.split(" ")[0] + text.split(" ")[1]).replace("H", "J"))

