in verify_credentials.py, opiutonal user input (depends on how user created their sign up page, some prefer to have username, some prefer to have emial, some rpefer to have none or even both)


In sending emial logic
The Salt
The salt is combined with the secret key to derive a unique key for distinguishing different contexts. Unlike the secret key, the salt doesn’t have to be random, and can be saved in code. It only has to be unique between contexts, not private.

For example, you want to email activation links to activate user accounts, and upgrade links to upgrade users to a paid accounts. If all you sign is the user id, and you don’t use different salts, a user could reuse the token from the activation link to upgrade the account. If you use different salts, the signatures will be different and will not be valid in the other context.
Also: key rotation for https://itsdangerous.palletsprojects.com/en/stable/concepts/#key-rotation (unsure on how it works tho)



for sending email, keeping it simple for now. just plain text. hard coded gmial, later give options 
There is a limit on smtp, add throttling or ip blacklisting to avoid hitting the limit.
✅ 2. SMTPConnectError
Trigger condition: Try connecting to an invalid server/port.


Surprisingly, all letters after @ in a domain is case insensitive but before CAN be case sensitive at times. (verify_recieved_detials.py class verifyemail)

read up on refresh token rotation
silent refresh, no silent refresh


https://developer.okta.com/blog/2019/08/22/okta-authjs-pkce, pkce for SPA especially, seperate server (like a true microframework)

https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/

(pkce for server and and authoirsation diff server)
(to keep it simple for now one monolithic backend, and 1 frontend)
refresh token as httponly
acces_token json body