import logging
from getpass import getpass
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

# first url; redirects to shibboleth, populates cookies
LOGIN_REDIR_URL = 'https://login.brandeis.edu/'

# app url; redirects to login
LATTE_URL = 'https://moodle2.brandeis.edu/'

LOGIN_PREFIX = 'https://shibboleth.brandeis.edu/idp/profile/SAML2/Redirect/SSO'

LOGOUT_URL = 'https://shibboleth.brandeis.edu/idp/profile/Logout'


def log_history(response: requests.models.Response):
    if not response.history:
        return
    logging.info('Request trail for ' + str(response.url))
    for entry in response.history:
        logging.info('- ' + str(entry.url))


def make_soup(response: requests.models.Response) -> BeautifulSoup:
    return BeautifulSoup(response.text, 'html.parser')


def form_defaults(form: BeautifulSoup) -> dict:
    return {input['name']: input['value'] for input in form.findAll('input') if input.has_attr('name')}


class Brandeis:
    def __init__(self):
        self.session = requests.session()
        self.logged_in = False

    def get(self, *args, **kwargs):
        return self.session.get(*args, **kwargs)

    def post(self, *args, **kwargs):
        return self.session.post(*args, **kwargs)

    def login(self, username, password):
        """
        Logs in the current session. If the session is already logged in, does nothing.
        :param username: the username to log in with; may not be empty
        :param password: the password to log in with
        :raises: ConnectionError if the login fails in any way
        :raises: ValueError if username is empty
        """
        if self.logged_in:
            return
        if not username:
            raise ValueError('Empty username not allowed')

        logging.info('Requesting login URL')
        # this request populates a session cookie
        req = self.get(LOGIN_REDIR_URL)
        if not req.ok:
            raise ConnectionError
        log_history(req)
        if self.session.cookies:
            logging.info('Cookies: ' + str(self.session.cookies))

        logging.info('Attempting to access LATTE to get login page')
        req = self.get(LATTE_URL)
        if not req.url.startswith(LOGIN_PREFIX):
            raise ConnectionError('LATTE login redirected to unexpected location: ' + str(req.url))
        logging.info('Login page: ' + req.url)
        log_history(req)

        # figure out where to POST to
        soup = make_soup(req)
        form = soup.find('form', {'name': 'f'})
        login_post = urljoin(req.url, form['action'])

        # fill out any hidden elements, although there don't seem to be any
        data = form_defaults(form)
        data.setdefault('_eventId_proceed', '')
        logging.info('Form data (except for username and password): ' + repr(data))
        data['j_username'] = username
        data['j_password'] = password

        logging.info('POSTing login to ' + login_post)
        req = self.post(login_post, data=data)
        if not req.ok:
            raise ConnectionError('Login request failed')
        log_history(req)

        soup = make_soup(req)
        err = soup.find('div', {'class': 'aui-message-error'}) or soup.find('p', {'class': 'form-error'})
        if err:
            raise ConnectionError(err.text)

        if not self.session.cookies['shib_idp_session_ss'] or not self.session.cookies['shib_idp_session']:
            raise ConnectionError('No Shibboleth session cookies set')

        form = soup.find('form')
        logging.info('Making redirect request')
        req = self.post(form['action'], data=form_defaults(form))
        if not req.ok:
            raise ConnectionError('Redirect request failed')
        log_history(req)

        if not req.url.startswith(LATTE_URL):
            raise ConnectionError("Login didn't redirect where expected")

        self.logged_in = True

    def logout(self):
        if not self.get(LOGOUT_URL).ok:
            raise ConnectionError


def main():
    logging.basicConfig(level=logging.INFO)
    login = Brandeis()
    username = input('Username: ')
    password = getpass()
    print(login.login(username, password))
    print('Authenticated LATTE homepage:')
    print(login.get(LATTE_URL).text)

    login.logout()


if __name__ == '__main__':
    main()
