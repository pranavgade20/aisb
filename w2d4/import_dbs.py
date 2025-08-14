import csv

from LegacySite.models import Product, User

def import_products(fname):
    for row in csv.reader(open(fname)):
        prod = Product.objects.create(
            product_id=row[0],
            product_name=row[1],
            product_image_path=row[2],
            recommended_price=row[3],
            description=row[4],
        )
        prod.save()

def import_users(fname):
    for row in csv.reader(open(fname)):
        user = User.objects.create(
            username=row[2],
            password=row[3],
        )
        user.save()

import_users('users.csv')
import_products('products.csv')
