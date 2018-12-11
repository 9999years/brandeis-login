A Python framework for automating logging into the Brandeis services.

    from brandeis_login import Brandeis
    session = Brandeis()
    try:
        session.login('some_username', 'secret_password')
    except ConnectionError as e:
        print('something went wrong!', e)
    # make an authenticated request to LATTE
    session.get('https://moodle2.brandeis.edu/')

A `Brandeis` object has a `get` and a `post` method, which both delegate to
[requests]; for more methods, use the `session` attribute:

    session.session.head('some_link')
    session.session.cookies['JSESSIONID']

Please don't put your password into source code. Use [getpass], a project
like [python-decouple], or just load the data from a `.json` file.

[python-decouple]: https://pypi.org/project/python-decouple/
[getpass]: https://docs.python.org/3/library/getpass.html
[requests]: http://docs.python-requests.org/en/master/
