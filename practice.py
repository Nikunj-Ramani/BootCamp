#!/usr/bin/python

print("1. Looping Through a String")
for i in "0123":
    print(i)
print('===============================\n')
print("2. The break Statement")
fruits = ["apple", "banana", "cherry"]
for x in fruits:
  print(x)
  if x == "banana":
    break
print('===============================\n')
print("3. The break Statement")
fruits = ["apple", "banana", "cherry"]
for x in fruits:
  if x == "banana":
    break
  print(x)
print('===============================\n')
print("4. The continue Statement")
fruits = ["apple", "banana", "cherry"]
for x in fruits:
  if x == "banana":
    continue
  print(x)
print('===============================\n')
print("5. The range() Function")
for x in range(3):
  print(x)
print('===============================\n')
for x in range(4, 6):
  print(x)  
print('===============================\n')
for x in range(2, 13, 4):
  print(x)
print('===============================\n')
print("6. The function")  
def my_function():
  print("Hello from a function")

my_function()    
print('===============================\n')
print("7. The function")  
def my_function(fname):
  print(fname + " --> My collegues")

my_function("Emil")
my_function("Tobias")
my_function("Linus")