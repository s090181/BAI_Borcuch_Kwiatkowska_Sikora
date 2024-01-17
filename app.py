from flask import Flask, flash, jsonify, render_template, request, redirect, url_for, session
from html import escape
import mysql.connector
import hashlib
import os
import re
from datetime import date
import pyotp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import string
from datetime import datetime, timedelta
import time
from flask_wtf import CSRFProtect
from TokenBucket import TokenBucket, forward, drop

app = Flask(__name__)
app.secret_key = "klucz_sesji"
csrf = CSRFProtect(app)
tokeny_na_sekunde = 18
max_tokeny = 20
token_bucket = TokenBucket(max_tokeny, tokeny_na_sekunde, forward, drop)

mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="biblioteka"
)


@app.before_request
def limit_requests():
    if request.path != url_for('error_429'):
        if token_bucket.handle(request):
            return render_template('error429.html'), 429


@app.route('/error_429')
def error_429():
    return render_template('error429.html')


def validate_name(name):
    return bool(re.match(r'^[A-Za-zęĘóÓąĄśŚłŁżŻźŹćĆńŃ]+$', name))


def validate(name):
    return bool(re.match(r'^[A-Za-z\s.,ęĘóÓąĄśŚłŁżŻźŹćĆńŃ]+$', name))


def validate_phone_number(number):
    return bool(re.match(r'^\d{9}$', number))


def validate_email(email):
    return bool(re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email))


def validate_password(password):
    return bool(re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$', password))


def validate_book_year(year_str):
    try:
        year = int(year_str)
        current_year = date.today().year
        return year > 0 and year <= current_year
    except ValueError:
        return False


def validate_positive_number(number_str):
    try:
        number = int(number_str)
        return number > 0
    except ValueError:
        return False


@app.route('/')
def index():
    session.pop('logged_in', None)
    session.pop('verified', None)
    return render_template('index.html')


@app.route('/register', methods=['GET'])
def register_form():
    session.pop('logged_in', None)
    session.pop('verified', None)
    return render_template('register.html')


@app.route('/register', methods=['POST'])
def register():
    session.pop('logged_in', None)
    session.pop('verified', None)
    imie = escape(request.form['imie'])
    nazwisko = escape(request.form['nazwisko'])
    numer_telefonu = escape(request.form['numer_telefonu'])
    email = escape(request.form['email'])
    nazwa_uzytkownika = escape(request.form['nazwa_uzytkownika'])
    haslo = escape(request.form['haslo'])

    error = None

    if not validate_name(imie) or not validate_name(nazwisko):
        error = "Niepoprawne imię lub nazwisko!"

    if not validate_phone_number(numer_telefonu):
        error = "Niepoprawny numer telefonu!"

    if not validate_email(email):
        error = "Niepoprawny adres email!"

    if not validate_password(haslo):
        error = "Niepoprawne hasło! Powinno posiadać conajmniej 8 znaków, w tym przynajmniej jedną małą literę, dużą literę oraz cyfrę."

    if error:
        return render_template('register.html', error=error)

    salt = os.urandom(32)
    hash = hashlib.pbkdf2_hmac("sha256", haslo.encode('utf-8'), salt, 10000)
    hexhash = (salt + hash).hex()

    cursor = mydb.cursor()
    query = "SELECT * FROM uzytkownicy WHERE nazwa_uzytkownika = %s OR email = %s"
    values = (nazwa_uzytkownika, email)
    cursor.execute(query, values)
    result = cursor.fetchone()

    if result:
        return render_template('register.html', error="Użytkownik o podanym loginie lub emailu już istnieje!")
    else:
        query = "INSERT INTO uzytkownicy (imie, nazwisko, numer_telefonu, email, nazwa_uzytkownika, haslo) VALUES (%s, %s, %s,%s, %s, %s)"
        values = (imie, nazwisko, numer_telefonu, email, nazwa_uzytkownika, hexhash)
        cursor.execute(query, values)
        mydb.commit()

        return redirect(url_for('login'))


def increase_login_attempts(cursor, username):
    cursor.execute("UPDATE uzytkownicy SET login_attempts = login_attempts + 1 WHERE nazwa_uzytkownika = %s",
                   (username,))
    mydb.commit()
    cursor.execute("SELECT login_attempts FROM uzytkownicy WHERE nazwa_uzytkownika = %s", (username,))
    login_attempts = cursor.fetchone()[0]

    if login_attempts >= 3:
        blocked_until = datetime.now() + timedelta(minutes=5)
        cursor.execute("UPDATE uzytkownicy SET blocked_until = %s, login_attempts = 0 WHERE nazwa_uzytkownika = %s",
                       (blocked_until, username,))
        mydb.commit()
        return blocked_until
    else:
        return None


def reset_login_attempts(cursor, username):
    cursor.execute("UPDATE uzytkownicy SET login_attempts = 0, blocked_until = NULL WHERE nazwa_uzytkownika = %s",
                   (username,))


def is_account_blocked(cursor, username):
    cursor.execute("SELECT blocked_until FROM uzytkownicy WHERE nazwa_uzytkownika = %s", (username,))
    blocked_until = cursor.fetchone()[0]

    if blocked_until and blocked_until > datetime.now():
        return True
    else:
        return False


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    session.pop('verified', None)
    session.pop('logged_in', None)

    if request.method == 'POST':
        nazwa_uzytkownika = escape(request.form['nazwa_uzytkownika'])
        haslo = escape(request.form['haslo'])

        cursor = mydb.cursor()
        query = "SELECT * FROM uzytkownicy WHERE nazwa_uzytkownika = %s"
        values = (nazwa_uzytkownika,)
        cursor.execute(query, values)
        result = cursor.fetchone()

        if result:
            if is_account_blocked(cursor, nazwa_uzytkownika):
                error = "Twoje konto jest zablokowane. Spróbuj ponownie za kilka minut."
            else:
                stored_hash = result[6]
                salt = bytes.fromhex(stored_hash[:64])
                expected_hash = stored_hash[64:]

                hash = hashlib.pbkdf2_hmac("sha256", haslo.encode('utf-8'), salt, 10000)
                hexhash = hash.hex()

                if hexhash == expected_hash:
                    session['logged_in'] = True
                    session['nazwa_uzytkownika'] = nazwa_uzytkownika

                    reset_login_attempts(cursor, nazwa_uzytkownika)

                    cursor.execute("SELECT email FROM uzytkownicy WHERE nazwa_uzytkownika = %s", (nazwa_uzytkownika,))
                    user = cursor.fetchone()

                    totp = pyotp.TOTP("tajnehaslotajnehaslo", interval=30)
                    pyotp_code = totp.now()

                    session['verification_code'] = {
                        'code': pyotp_code,
                        'expiration_time': time.time() + 30
                    }

                    query = "UPDATE uzytkownicy SET verification_code = %s WHERE nazwa_uzytkownika = %s"
                    values = (pyotp_code, nazwa_uzytkownika)
                    cursor.execute(query, values)
                    mydb.commit()

                    sender_email = "kiegarnia8@gmail.com"
                    receiver_email = user[0]
                    password_email = "sfhxleosktquvdzx"
                    message = MIMEMultipart()
                    message["From"] = sender_email
                    message["To"] = receiver_email
                    message["Subject"] = "Twój kod weryfikacyjny"
                    body = f"Kod: {pyotp_code}"
                    message.attach(MIMEText(body, "plain"))
                    with smtplib.SMTP("smtp.gmail.com", 587) as server:
                        server.starttls()
                        server.login(sender_email, password_email)
                        text = message.as_string()
                        server.sendmail(sender_email, receiver_email, text)

                    return redirect(url_for('weryfikacja'))
                else:
                    blocked_until = increase_login_attempts(cursor, nazwa_uzytkownika)
                    if blocked_until:
                        error = f"Nieprawidłowe dane logowania. Twoje konto zostało zablokowane."
                    else:
                        error = "Dane są nieprawidłowe, spróbuj jeszcze raz."

        else:
            error = "Dane są nieprawidłowe, spróbuj jeszcze raz."

    else:
        session.pop('logged_in', None)
        session.pop('nazwa_uzytkownika', None)

    return render_template('login.html', error=error)


@app.route('/weryfikacja', methods=['GET', 'POST'])
def weryfikacja():
    error = None
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        kod_weryfikacyjny = escape(request.form['kod_weryfikacyjny'])
        nazwa_uzytkownika = session.get('nazwa_uzytkownika')

        stored_verification_code = session.get('verification_code')

        if stored_verification_code and time.time() < stored_verification_code['expiration_time']:
            if kod_weryfikacyjny == stored_verification_code['code']:
                session['verified'] = True
                return redirect(url_for('strona_glowna'))
            else:
                error = "Nieprawidłowy kod weryfikacyjny!"
        else:
            error = "Błąd weryfikacji lub kod wygasł!"

    return render_template('weryfikacja.html', error=error)


@app.route('/change_pass', methods=['GET', 'POST'])
def change_pass():
    session.pop('logged_in', None)
    session.pop('verified', None)
    error = None

    if request.method == 'POST':
        email = escape(request.form['email'])

        if not validate_email(email):
            error = "Niepoprawny adres email!"

        if error:
            return render_template('change_pass.html', error=error)

        cursor = mydb.cursor()
        cursor.execute("SELECT COUNT(*) FROM uzytkownicy WHERE email = %s", (email,))
        result = cursor.fetchone()

        if result[0] > 0:
            haslo_gen = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            if any(c.islower() for c in haslo_gen) and any(c.isupper() for c in haslo_gen) and any(
                    c.isdigit() for c in haslo_gen):
                sender_email = "kiegarnia8@gmail.com"
                receiver_email = email
                password_email = "sfhxleosktquvdzx"
                message = MIMEMultipart()
                message["From"] = sender_email
                message["To"] = receiver_email
                message["Subject"] = "Twoje nowe hasło"
                body = f"Hasło: {haslo_gen}"
                body_bytes = body.encode('utf-8')
                message.attach(MIMEText(body_bytes, "plain", "utf-8"))
                with smtplib.SMTP("smtp.gmail.com", 587) as server:
                    server.starttls()
                    server.login(sender_email, password_email)
                    server.send_message(message)

                salt = os.urandom(32)
                hash = hashlib.pbkdf2_hmac("sha256", haslo_gen.encode('utf-8'), salt, 10000)
                hexhash = (salt + hash).hex()

                cursor.execute("UPDATE uzytkownicy SET haslo = %s WHERE email = %s", (hexhash, email))
                mydb.commit()

                return redirect(url_for('login'))
        else:
            error = "Konto o podanym email nie istnieje!"

    return render_template('change_pass.html', error=error)


@app.route('/strona_glowna', methods=['GET'])
def strona_glowna():
    if not session.get('verified'):
        return redirect(url_for('login'))

    cursor = mydb.cursor()
    query = "SELECT * FROM ksiazki"
    cursor.execute(query)
    books = cursor.fetchall()

    return render_template('strona_glowna.html', books=books)


@app.route('/profil')
def profil(error_message=None, success_message=None):
    if not session.get('verified'):
        return redirect(url_for('login'))

    cursor = mydb.cursor()
    query = "SELECT * FROM uzytkownicy WHERE nazwa_uzytkownika = %s"
    values = (session['nazwa_uzytkownika'],)
    cursor.execute(query, values)
    user = cursor.fetchone()

    return render_template('user_panel.html', user=user, error_message=error_message, success_message=success_message)


@app.route('/zmien_haslo', methods=['POST'])
def zmien_haslo():
    if not session.get('verified'):
        return redirect(url_for('login'))

    stare_haslo = escape(request.form['stare_haslo'])
    nowe_haslo = escape(request.form['nowe_haslo'])

    error = None

    if not validate_password(stare_haslo):
        error = "Niepoprawne stare hasło! Powinno posiadać co najmniej 8 znaków, w tym przynajmniej jedną małą literę, dużą literę oraz cyfrę."

    if not validate_password(nowe_haslo):
        error = "Niepoprawne nowe hasło! Powinno posiadać co najmniej 8 znaków, w tym przynajmniej jedną małą literę, dużą literę oraz cyfrę."

    if error:
        return profil(error_message=error)

    cursor = mydb.cursor()
    query = "SELECT * FROM uzytkownicy WHERE nazwa_uzytkownika = %s"
    values = (session['nazwa_uzytkownika'],)
    cursor.execute(query, values)
    result = cursor.fetchone()

    if result:
        stored_hash = result[6]
        salt = bytes.fromhex(stored_hash[:64])
        expected_hash = stored_hash[64:]

        hash = hashlib.pbkdf2_hmac("sha256", stare_haslo.encode('utf-8'), salt, 10000)
        hexhash = hash.hex()

        if hexhash == expected_hash:
            new_salt = os.urandom(32)
            new_hash = hashlib.pbkdf2_hmac("sha256", nowe_haslo.encode('utf-8'), new_salt, 10000)
            new_hexhash = (new_salt + new_hash).hex()

            query = "UPDATE uzytkownicy SET haslo = %s WHERE nazwa_uzytkownika = %s"
            values = (new_hexhash, session['nazwa_uzytkownika'])
            cursor.execute(query, values)
            mydb.commit()
            return profil(success_message="Hasło zostało pomyślnie zaktualizowane!")
        else:
            error = "Niepoprawnie wpisane obecne hasło, spróbuj jeszcze raz!"
            return profil(error_message=error)
    else:
        return redirect(url_for('login'))


@app.route('/edytuj_dane', methods=['POST'])
def edytuj_dane():
    if not session.get('verified'):
        return redirect(url_for('login'))

    imie = escape(request.form['imie'])
    nazwisko = escape(request.form['nazwisko'])
    numer_telefonu = escape(request.form['numer_telefonu'])
    email = escape(request.form['email'])
    nazwa_uzytkownika = escape(request.form['nazwa_uzytkownika'])

    error = None

    if not validate_name(imie) or not validate_name(nazwisko):
        error = "Niepoprawne imię lub nazwisko!"

    if not validate_phone_number(numer_telefonu):
        error = "Niepoprawny numer telefonu!"

    if not validate_email(email):
        error = "Niepoprawny adres email!"

    if error:
        return profil(error_message=error), 200

    cursor = mydb.cursor()
    query = "UPDATE uzytkownicy SET imie = %s, nazwisko = %s, numer_telefonu = %s, email = %s WHERE nazwa_uzytkownika = %s"
    values = (imie, nazwisko, numer_telefonu, email, nazwa_uzytkownika)
    cursor.execute(query, values)
    mydb.commit()

    return redirect(url_for('profil'))


@app.route('/dodaj_ksiazke', methods=['GET', 'POST'])
def dodaj_ksiazke():
    if not session.get('verified'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        tytul = escape(request.form['tytul'])
        autor = escape(request.form['autor'])
        wydawnictwo = escape(request.form['wydawnictwo'])
        seria = escape(request.form['seria'])
        oprawa = escape(request.form['oprawa'])
        rok_wydania = escape(request.form['rok_wydania'])
        ilosc_stron = escape(request.form['ilosc_stron'])
        rzad = escape(request.form['rzad'])
        regal = escape(request.form['regal'])
        polka = escape(request.form['polka'])

        errors = []

        if not validate(autor):
            errors.append("Nieprawidłowy autor książki")

        if not validate_name(oprawa):
            errors.append("Nieprawidłowy rodzaj oprawy książki!")

        if not validate_book_year(rok_wydania):
            errors.append("Niepoprawny rok wydania książki!")

        if not validate_positive_number(ilosc_stron):
            errors.append("Nieprawidłowa liczba stron!")

        if not validate_positive_number(rzad):
            errors.append("Nieprawidłowy numer rzędu!")

        if not validate_positive_number(regal):
            errors.append("Nieprawidłowy numer regału!")

        if not validate_positive_number(polka):
            errors.append("Nieprawidłowy numer półki!")

        if errors:
            return render_template('dodaj_ksiazke.html', errors=errors)

        cursor = mydb.cursor()
        query = "INSERT INTO ksiazki (tytul, autor, wydawnictwo, seria, oprawa, rok_wydania, ilosc_stron, rzad, regal, polka) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        values = (tytul, autor, wydawnictwo, seria, oprawa, rok_wydania, ilosc_stron, rzad, regal, polka)
        cursor.execute(query, values)
        mydb.commit()

        return redirect(url_for('strona_glowna'))
    else:
        return render_template('dodaj_ksiazke.html')


@app.route('/usun_ksiazke/<int:book_id>', methods=['POST'])
def usun_ksiazke(book_id):
    if not session.get('verified'):
        return redirect(url_for('login'))

    cursor = mydb.cursor()
    query = "DELETE FROM ksiazki WHERE id = %s"
    values = (book_id,)
    cursor.execute(query, values)
    mydb.commit()

    return redirect(url_for('strona_glowna'))


@app.route('/edytuj_ksiazke/<int:ksiazka_id>', methods=['GET', 'POST'])
def edytuj_ksiazke(ksiazka_id):
    if not session.get('verified'):
        return redirect(url_for('login'))

    cursor = mydb.cursor()
    errors = []

    if request.method == 'POST':
        tytul = escape(request.form['tytul'])
        autor = escape(request.form['autor'])
        wydawnictwo = escape(request.form['wydawnictwo'])
        seria = escape(request.form['seria'])
        oprawa = escape(request.form['oprawa'])
        rok_wydania = escape(request.form['rok_wydania'])
        ilosc_stron = escape(request.form['ilosc_stron'])
        rzad = escape(request.form['rzad'])
        regal = escape(request.form['regal'])
        polka = escape(request.form['polka'])

        if not validate(autor):
            errors.append('Nieprawidłowy autor książki!')

        if not validate_name(oprawa):
            errors.append('Nieprawidłowy rodzaj oprawy książki!')

        if not validate_book_year(rok_wydania):
            errors.append('Nieprawidłowy rok wydania książki!')

        if not validate_positive_number(ilosc_stron):
            errors.append('Nieprawidłowa liczba stron!')

        if not validate_positive_number(rzad):
            errors.append('Nieprawidłowy numer rzędu!')

        if not validate_positive_number(regal):
            errors.append('Nieprawidłowy numer regału!')

        if not validate_positive_number(polka):
            errors.append('Nieprawidłowy numer półki!')

        if errors:
            for error in errors:
                flash(error, 'error')
            return redirect(url_for('edytuj_ksiazke', ksiazka_id=ksiazka_id))

        query = "UPDATE ksiazki SET tytul = %s, autor = %s, wydawnictwo = %s, seria = %s, oprawa = %s, rok_wydania = %s, ilosc_stron = %s, rzad = %s, regal = %s, polka = %s WHERE id = %s"
        values = (tytul, autor, wydawnictwo, seria, oprawa, rok_wydania, ilosc_stron, rzad, regal, polka, ksiazka_id)
        cursor.execute(query, values)
        mydb.commit()

        return redirect(url_for('strona_glowna'))
    else:
        query = "SELECT * FROM ksiazki WHERE id = %s"
        values = (ksiazka_id,)
        cursor.execute(query, values)
        book = cursor.fetchone()

        return render_template('edytuj_ksiazke.html', book=book)


@app.route('/wyszukaj_ksiazke', methods=['GET', 'POST'])
def wyszukaj_ksiazke():
    if not session.get('verified'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        tytul = escape(request.form['tytul'].lower())
        autor = escape(request.form['autor'].lower())
        wydawnictwo = escape(request.form['wydawnictwo'].lower())
        seria = escape(request.form['seria'].lower())
        oprawa = escape(request.form['oprawa'].lower())
        rok_wydania = escape(request.form['rok_wydania'])
        ilosc_stron = escape(request.form['ilosc_stron'])
        rzad = escape(request.form['rzad'])
        regal = escape(request.form['regal'])
        polka = escape(request.form['polka'])

        errors = []

        if autor and not validate(autor):
            errors.append("Nieprawidłowy autor książki")

        if oprawa and not validate_name(oprawa):
            errors.append("Nieprawidłowy rodzaj oprawy książki!")

        if rok_wydania and not validate_book_year(rok_wydania):
            errors.append("Niepoprawny rok wydania książki!")

        if ilosc_stron and not validate_positive_number(ilosc_stron):
            errors.append("Nieprawidłowa liczba stron!")

        if rzad and not validate_positive_number(rzad):
            errors.append("Nieprawidłowy numer rzędu!")

        if regal and not validate_positive_number(regal):
            errors.append("Nieprawidłowy numer regału!")

        if polka and not validate_positive_number(polka):
            errors.append("Nieprawidłowy numer półki!")

        if errors:
            return render_template('wyszukaj_ksiazke.html', errors=errors)

        cursor = mydb.cursor()
        query = "SELECT * FROM ksiazki WHERE 1=1"
        values = []

        if tytul:
            query += " AND LOWER(tytul) LIKE %s"
            values.append('%' + tytul + '%')

        if autor:
            query += " AND LOWER(autor) LIKE %s"
            values.append('%' + autor + '%')

        if wydawnictwo:
            query += " AND LOWER(wydawnictwo) LIKE %s"
            values.append('%' + wydawnictwo + '%')

        if seria:
            query += " AND LOWER(seria) LIKE %s"
            values.append('%' + seria + '%')

        if oprawa:
            query += " AND LOWER(oprawa) LIKE %s"
            values.append('%' + oprawa + '%')

        if rok_wydania:
            query += " AND rok_wydania LIKE %s"
            values.append('%' + rok_wydania + '%')

        if ilosc_stron:
            query += " AND ilosc_stron LIKE %s"
            values.append('%' + ilosc_stron + '%')

        if rzad:
            query += " AND LOWER(rzad) LIKE %s"
            values.append('%' + rzad + '%')

        if regal:
            query += " AND LOWER(regal) LIKE %s"
            values.append('%' + regal + '%')

        if polka:
            query += " AND LOWER(polka) LIKE %s"
            values.append('%' + polka + '%')

        cursor.execute(query, values)
        books = cursor.fetchall()

        return render_template('wyszukaj_ksiazke.html', books=books)
    else:
        return render_template('wyszukaj_ksiazke.html', books=[])


@app.route('/wyloguj')
def wyloguj():
    session.pop('logged_in', None)
    session.pop('verified', None)
    session.pop('nazwa_uzytkownika', None)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
