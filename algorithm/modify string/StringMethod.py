txt = "Hello, welcome To my World."
mot = "banAna"
mots = "b\ta\tn\tA\tn\ta"

email = "bemazava@youthcomputing.com"

#Expected output: Hello, welcome to my world
print(txt.capitalize())

#Expected output: hello, welcome to my world
print(txt.casefold())

#Expected output: oobananaoo
print(mot.center(10, "o"))
#Expected output: banana
print(mot.center(6))
#EXpected output: '''banana'''
print(mot.center(12,"'"))

#Return the number of time the value "a" appears in string. Expected output: 2
print(mot.count("a"))
print(txt.count("l"))

#count the number of times the value "l" appears in string from 1 to 10 position. output: 3
print(txt.count("l", 1, 10))

#count the number of times the value "e" appears in string from 1 to 11 position. output: 2
print(txt.count("e", 1, 11))

#encode the string 
print(txt.encode())
print(mot.encode())

# uses ascii encoding, and a character that cannot be encoded, showing the result with different errors:
print(txt.encode(encoding="ascii", errors="backslashreplace"))
print(txt.encode(encoding="ascii",errors="ignore"))
print(txt.encode(encoding="ascii", errors="namereplace"))
print(txt.encode(encoding="ascii", errors="replace" ))
print(txt.encode(encoding="ascii", errors="xmlcharrefreplace"))
print(mot.encode(encoding="ascii", errors="xmlcharrefreplace"))

#check if the string ends with @youthcomputing.com
print(email.endswith("@youthcomputing.com"))

#check if the string ends with .mg
print(email.endswith(".mg"))

#check if the string ends with @youthcomputing.mg
print(email.endswith("@youthcomputing.mg"))

#Check if position 5 to 11 ends with the phrase "my world."
print(txt.endswith("welcome", 5, 11))

#check if position 0 to 15 ends with the phrase "welcome"
print(txt.endswith("my World.", 0, 15))

#Set the tab size to 8 whitespaces default: Expected output: b      a       n       a       n       a
print(mots.expandtabs())

#Set the tab size to 2 whitespaces: Expected output: b a n a n a
print(mots.expandtabs(2))

# find the word welcome in the text output: 7
print(txt.find("welcome"))
#find the charactere "e" in the text output: -1
print(txt.find("x"))
#find the charactere "e" in the text output: 1
print(txt.find("e"))

#find the charactere "welcome" 