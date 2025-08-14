# CSRF
Protect GET route with CSRF doesn't work using djago builtins AFAIK. If you want to do that you need to implement by yourself. Besides, using GET request for that is not a good design, POST request would be more appropriate as it's intended to mutate things in backend.
If you want to test that exercise CSRF is working, you can "curl -X POST http://localhost:8000/gift/1" if you are getting a html page that say more or less "don't try to trick me" you good I guess
