from django.test import TestCase

# Create your tests here.


from database import Database
from bson import ObjectId

db = Database()

this = db.list_files(ObjectId('56deae56695b263a60d4e0c3'))
for t in this:
    print t

