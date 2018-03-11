# SAML2.0 WebSSO with angular client

Some developers asked me how to handle saml authentication with an angular application.

This repo is a sample code repo to show a basic way to do it.

## angular-saml-client

is the client angular app build with the angular cli 1.7.3.

### How to

```
cd angular-saml-client/
```

```
npm install
```

```
npm run start
```

Open [http://localhost:4200](http://localhost:4200) with your browser

### Proxy configuration

The app use a reverse proxy configuration for backend to avoid CORS. Every call to http://localhost:4200/service/
will be reverse proxied to http://localhost:8080/

The reverse proxy config is stored in proxy.conf.json


## saml-jwt-sample

is the backend Service Provider (in Saml Terms). 

It's a fork of my repo [https://github.com/slem1/saml-jwt-sample](https://github.com/slem1/saml-jwt-sample). 

Please see also my previous blog post about SAML2.0 WebSSO: [https://www.sylvainlemoine.com/2016/06/06/spring-saml2.0-websso-and-jwt-for-mobile-api/](https://www.sylvainlemoine.com/2016/06/06/spring-saml2.0-websso-and-jwt-for-mobile-api/)

This fork add the use of the RelayState saml parameter to redirect user to the angular app when authentication is successful.

As the original repo it makes use of SSOCircle [https://www.ssocircle.com/en/](https://www.ssocircle.com/en/) as SAML Identity Provider. 

This backend is intended to run on localhost:8080.

This repo can be used as a starter for more sophisticated about saml authentication with Single Page Application.

## License

The MIT License

Copyright (c) 2010-2018 Google, Inc. http://angularjs.org

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.