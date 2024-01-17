import unittest
from bs4 import BeautifulSoup
from app import app,login, edytuj_dane, edytuj_ksiazke, validate_name, validate_phone_number, validate_email, validate_password, validate_book_year, validate_positive_number, validate, change_pass  # replace 'your_app' with the actual name of your Flask application

class AuthenticationTestCase(unittest.TestCase):
    def setUp(self):
        app.config['WTF_CSRF_ENABLED'] = False
        self.app = app.test_client()
        self.app.testing = True

    def test_validate_name(self):
        valid_name = "John"
        self.assertTrue(validate_name(valid_name))

        invalid_name = "John123"
        self.assertFalse(validate_name(invalid_name))

    def test_validate_phone_number(self):
        valid_number = "123456789"
        self.assertTrue(validate_phone_number(valid_number))

        invalid_number = "1234"
        self.assertFalse(validate_phone_number(invalid_number))

    def test_validate_email(self):
        valid_email = "test@example.com"
        self.assertTrue(validate_email(valid_email))

        invalid_email = "testexample.com"
        self.assertFalse(validate_email(invalid_email))

    def test_validate_password(self):
        valid_password = "Passw0rd"
        self.assertTrue(validate_password(valid_password))

        invalid_password = "password"
        self.assertFalse(validate_password(invalid_password))

    def test_validate_book_year(self):
        valid_year = "2021"
        self.assertTrue(validate_book_year(valid_year))

        invalid_year = "abcd"
        self.assertFalse(validate_book_year(invalid_year))

    def test_validate_positive_number(self):
        valid_number = "10"
        self.assertTrue(validate_positive_number(valid_number))

        invalid_number = "-5"
        self.assertFalse(validate_positive_number(invalid_number))

    def test_validate(self):
        valid_text = "John Doe"
        self.assertTrue(validate(valid_text))

        invalid_text = "John Doe 123"
        self.assertFalse(validate(invalid_text))
    
    def test_app(self):
        self.assertEqual(self.app.get("/").status_code, 200)

    def test_profil(self):
        self.assertEqual(self.app.get("/profil").status_code, 302)
    
    def test_change_password_ok(self):
        old = "pasW0rdd"
        new = "pasW0rd1"

        data = {"stare_haslo": old, "nowe_haslo": new}
        response = self.app.post("/zmien_haslo", data=data)

        self.assertEqual(response.status_code, 302, response.data)

    def test_register_wrong_passwd(self):
        name = "John"
        surname = "Smith"
        tel_no = "668753201"
        email = "dummy.mail@mail.com"
        passwd = "Passwo1rdo"
        username = "johnsmith"

        data = {"imie": name, "nazwisko": surname, "numer_telefonu": tel_no, "email": email, "haslo": passwd, "nazwa_uzytkownika": username}
        response = self.app.post("/register", data=data)

        self.assertEqual(response.status_code, 200, response.data)
    

    def test_login_success(self):
        response = self.app.post('/login', data=dict(
            nazwa_uzytkownika='test_user',
            haslo='test_password'
        ), follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Zaloguj', response.data) 

    def test_login_failure(self):
        response = self.app.post('/login', data=dict(
            nazwa_uzytkownika='nonexistent_user',
            haslo='wrong_password'
        ), follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        soup = BeautifulSoup(response.data, 'html.parser')
        error_message = soup.find('div', {'class': 'error-message'})
        self.assertIsNotNone(error_message)
        self.assertIn('Dane są nieprawidłowe, spróbuj jeszcze raz.', error_message.text)


    def test_register_success(self):
        response = self.app.post('/register', data=dict(
            imie='John',
            nazwisko='Doe',
            numer_telefonu='123456789',
            email='john.doe@example.com',
            nazwa_uzytkownika='john_doe',
            haslo='Test1234'
        ), follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Zaloguj', response.data)

    def test_register_failure(self):
        response = self.app.post('/register', data=dict(
            imie='John',
            nazwisko='Doe',
            numer_telefonu='123569874',
            email='johndoe@wp.pl',
            nazwa_uzytkownika='johndoe',
            haslo='Long123'
        ), follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        soup = BeautifulSoup(response.data, 'html.parser')
        error_message = soup.find('p', {'style': 'color: red'})
        self.assertIsNotNone(error_message)
        self.assertIn('Niepoprawne hasło!', error_message.text)

    def test_weryfikacja_page_redirects_to_login_if_not_logged_in(self):
        response = self.app.get('/weryfikacja', follow_redirects=True)
        self.assertIn(b'Login', response.data)

    def tearDown(self):
        pass

if __name__ == '__main__':
    unittest.main()
