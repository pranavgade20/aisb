import io
import unittest
import json
from django.test import TestCase, Client
from django.db import connection
from LegacySite.models import Card, User

"""
Test Database Isolation: 
Each test in Django runs in isolation with a separate test database. 
This means that any data created, modified, or deleted in one test will not affect other tests. 
The test database is created at the start of the test run and destroyed at the end.
"""


class MyTest(TestCase):
    # TODO: READ THIS AND COMPLETE THIS FIRST BEFORE YOU RUN THE TESTS PROVIDED!
    # Django's test run with an empty database.
    # We can populate it with data by using a fixture.
    # Note that for the fixture to be populated correctly, you must complete migrations and imports!
    # You can create the fixture by running:
    #    mkdir LegacySite/fixtures
    #    python manage.py dumpdata LegacySite --indent=4> LegacySite/fixtures/testdata.json
    # You can read more about fixtures here:
    #    https://docs.djangoproject.com/en/4.0/topics/testing/tools/#fixture-loading
    # When you create your fixture, remember to uncomment the line where, fixtures = ["testdata.json"]
    # fixtures = ["testdata.json"]

    """
    Setup Method: 
    In the setUp method, you're creating a new Client instance. 
    This instance is unique for each test method and maintains its own session. 
    Therefore, when you register and log in a user within a test method, 
    the session is specific to this Client instance and that test method.
    
    setUp() is called everytime before a function starting with 'test_' is executed.
    Note that to be visible to `python3 manage.py test`, the python file must start with 'test'
    """
    def setUp(self):
        # Register and login our user to correctly handle session
        self.client = Client()
        self.username, self.password = 'test', 'test'
        self.register_user(self.username, self.password)
        self.client.login(username=self.username, password=self.password)

    def register_user(self, username, password):
        endpoint = '/register'
        data = {'uname': username,
                'pword': password, 
                'pword2': password}
        self.client.post(path=endpoint, data=data)
        canLogin = self.client.login(username=username, password=password)
        self.assertTrue(canLogin)

    # Assuming that your database had at least no Card in it,
    # this test should pass.
    def test_get_card(self):
        all_cards = Card.objects.all()
        self.assertEqual(len(all_cards), 0)

    def test_buy(self):
        # Make requests to our endpoint and ensure it returned status code 200
        response = self.client.get('/buy/0')
        self.assertEqual(response.status_code, 200)

        # Set our endpoint and data 
        response = self.client.post('/buy/0', {'amount': 100})
        self.assertEqual(response.status_code, 200)

    def test_check_card_data_using_SQL_query(self):
        # Recall each test run in isolation
        # Lets buy a card for this test
        self.test_buy()

        # One way to get a card using a raw SQL query
        cursor = connection.cursor()
        card_query = f"select * from LegacySite_card"
        cards = cursor.execute(card_query).fetchall()
        self.assertNotEqual(cards, [])
        card = cards[0]

        print("\nPrinting card found by using raw SQL query")
        print(card)

    def test_check_card_data_using_Django_ORM(self):
        # Let us buy a card for this test
        self.test_buy()
        user = User.objects.get(username=self.username)

        # Another way to get a card using Django ORM
        card = Card.objects.filter(user=user.pk).order_by('-id')[0]
        card_data = card.data.decode()
        card_data_dict = json.loads(card_data)
        signature = card_data_dict['records'][0]['signature']
        print("\nPrinting card found by using Django ORM")
        print("Card ID: " + str(card.id))
        print("Card Data: " + card_data)
        print("Card Used: " + str(card.used))
        print("Card Signature: " + signature)

    def test_buy_and_use_giftcard_by_selecting(self):
        self.test_buy()

        # We bought a card, so it should be in our database
        user = User.objects.get(username=self.username)
        card = Card.objects.filter(user=user.pk).order_by('-id')[0]

        # The user should be able to use a card by selecting it at the /use endpoint
        # The request would look like the following
        response = self.client.post('/use.html', {'card_id': card.id})
        self.assertEqual(response.status_code, 200, msg='Confirm that the POST request to use Giftcard amount 101')

    # You can also skip tests by changing the condition.
    @unittest.skipIf(True, "Skipping test_buy_and_use_giftcard_by_uploading")
    def test_buy_and_use_giftcard_by_uploading(self):
        # Make a request to our endpoint and ensure it returned status code 200
        response = self.client.post('/buy/0', {'amount': 102})
        self.assertEqual(response.status_code, 200)

        # We bought a card, so it should be in our database
        user = User.objects.get(username=self.username)
        card = Card.objects.filter(user=user.pk).order_by('-id')[0]

        # When we buy a card, the site also returns the card data
        card_data = response.content

        # Now we can upload a giftcard
        data = {
            'card_supplied': 'True',
            'card_fname': 'Test',
            'card_data': io.BytesIO(card_data),
            }
        response = self.client.post('/use.html', data)
        self.assertEqual(response.status_code, 200, msg='Confirm that the request to /use Giftcard works')
        
        # We can also verify that the card was used by checking the response and the database
        self.assertIn('Card used!', response.content.decode())
        self.assertTrue(Card.objects.get(pk=card.id).used, msg='Checking the database, it says the giftcard wasn\'t used.')
