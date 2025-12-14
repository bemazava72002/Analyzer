txt = "Hello, welcome To my World."
mot = "banAna"
mots = "b\ta\tn\tA\tn\ta"
tx = "\u0033"

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
#Where in the text is the "word" output: 21
print(txt.index("World"))

#Find the first occurence of the letter "e"?:
print(txt.index("e"))

#find the first occurrence of the letter "e" when you only search between position 5 and 10?
print(txt.index("e",5,10))

#If the value is not found, the find() method returns -1, but the index() method will raise an exception:
print(txt.find("q"))


#Check if all the characters in the text are whitespaces: output: False
print(txt.isspace())

#Check if each word start with an upper case letter: output: False
print(txt.istitle())

#Check if all the characters in the text are letters: Output: False because whitespace, comma
print(txt.isalpha())

#Check if all the characters in the unicode object are decimals: output: True
print(tx.isdecimal())

#Join all items in a tuple into a string, using a hash character as separator: output: banana#orange#lemon
mytuple = ("banana","orange","lemon")
print("#".join(mytuple))

#The join() method takes all items in an iterable and joins them into one string.

#A string must be specified as the separator.

#Syntax
#string.join(iterable)
#Join all items in a dictionary into a string, using a the word "TEST" as separator: output: nameTestcountry
myDict = {"name":"julio","country":"Madagascar"}
mytext = "Test"

print(mytext.join(myDict))

#Return a 20 characters long, left justified version of the word "banana": output: banana               is my favorite fruit
ba = "banana"

x = ba.ljust(20)

print(x, "is my favorite fruit")

#Using the letter "O" as the padding character: output:bananaOOOOOOOOOOOOOO is my favorite fruit
y = ba.ljust(20, "O")
print(y, "is my favorite fruit")


#Remove spaces to the left of the string: output: of all fruit banana is my favorite
t1 = "     banana"
z = t1.lstrip()
print("of all fruit",z,"is my favorite")

#Remove the leading characters: output: banana
t2 =  ",,,,,ssaaww.....banana"
t = t2.lstrip(",.asw")
print(t)

#Create a mapping table, and use it in the translate() method to replace any "S" characters with a "P" character: output:Hello, Pam
t3 = "Hello, Sam"
e = t3.maketrans("S","P")
print(t3.translate(e))

te = "Hi Sam!"

r = "mSa"
u = "ejo"


#Use a mapping table to replace many characters output:Hi joe!
mytable = te.maketrans(r,u)
print(te.translate(mytable))

#The third parameter in the mapping table describes characters that you want to remove from the string:
text1 = "Good night, jul"

tex1 = "mSa"
tex2 = "ejo"
third = "odnght"
mytab = tex1.maketrans(tex1,tex2, third)
print(text1.translate(mytab))