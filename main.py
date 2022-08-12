import base64
import hmac
import hashlib
from typing import Optional
from flask import Flask, render_template, request, make_response


app = Flask(__name__)

PASSWORD_SALT = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
SECRET_KEY = 's73ef2a4edd7a7fbf07fd5f6faf99674dc0c25a025fd74c221f4c35849e5c0fb3'

users = {
    'viktor@user.com': {
        'name': 'Viktor',
        'password': '7984dfec1e14ef78ba36c4be872a4f34ecb4af3684ccf391725506bb1fd24abd',
        'Age ': 19
    },
    'petr@user.com': {
        'name': 'Petr',
        'password': 'b0e678b6718c8dcbffe4fbfc5e5cebf41d4261472c676f365a8a2c4a9d15578f',
        'Age ': 19
    }
}


def sign_data(data: str) -> str:
    """Возращает подписанные данные data"""
    encode_b64 = base64.b64encode(data.encode()).decode()
    hech = hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256).hexdigest().upper()

    rezult = encode_b64 + '.' + hech
    return rezult


def verification_password(login: str, password: str) -> bool:
    """функция проверки пароля"""
    hash_password = hashlib.sha256(
        (password+PASSWORD_SALT). encode()).hexdigest().lower()
    true_password = users[login]['password'].lower()
    if hash_password != true_password:
        return False
    return True


def get_login_from_signed_strint(login_signed: str) -> Optional[str]:
    """Производит проверку подписи cookis, \n
    возращает дешифрованый Логин или None"""
    login, sing = login_signed.split('.')
    login = base64.b64decode(login.encode()).decode()
    valid_login, valid_sing = sign_data(login).split('.')

    if hmac.compare_digest(valid_sing, sing):
        return login

#login: Optional[str] = Cookie(default=None)
# Отправвка GET запроса


@app.route('/', methods=['GET'])
def index():
    login = request.cookies.get('login')
    if not login:
        return render_template('index.html')  # Отрисовка главной страницы

    valid_login = get_login_from_signed_strint(login) # Проверка подписи, а также валидности логина
    if not valid_login:
        respons = make_response(render_template('index.html'))
        respons.delete_cookie('login')
        return respons

    try:
        user = users[valid_login] # Получение username
    except KeyError:
        response = make_response(render_template('index.html'))
        response.delete_cookie(key='login')
        return response

    return render_template('answer.html', username=user['name'])# Ответ на POST запрос


# Получение POST запроса
@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        if not request.form['login'] in users:
            return '[INFO] Не введены Логин и Пароль'

        login = request.form['login']
        password = request.form['password']
        if verification_password(login, password):
            username = users[login]['name']
            respons = make_response(render_template('answer.html', username=username))
            login_signed = sign_data(login)
            # установка Cookies
            respons.set_cookie('login', login_signed)
            return respons

    return 'Я вас не знаю!'


# Выход из аккаунта
@app.route('/', methods=['POST'])
def exit():
    if request.form['exit']:# Отрисовка главной страницы и удание Cookies
        respons = make_response(render_template('index.html'))
        respons.delete_cookie('login')
        return respons


if __name__ == '__main__':
    app.run(port='8000', debug=True)
