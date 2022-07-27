sum=0
a = str(input('Enter string '))
x = list(a)
for y in x:
    val=ord(y) - 96
    print(val)
    sum+=val

print("Total for the word is")
print(sum)
#Done to check son's homework :)
