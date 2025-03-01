## tredictpy

Python package to interact with [Tredict](https://www.tredict.com/) - a training platform for data lovers.

To apply for access to the API see here: [Tredict API](https://www.tredict.com/blog/oauth_docs/)

Once you have credentials, etc, enter these in the `example-tredcit-config.py` add rename it to `tredict-config.py`. Start using the package:

```
import tredictpy

# Client with default config file
client = TredictPy()

# Provides auth URL and starts a callback server
client.request_auth_code()

# Request and access token
client.request_user_access_token()

# Fetch a list of all activities on your profile
client.activity_list()

# Deregister
client.deregister()
```

View the docs at: [tredictpy docs](https://danieldean.github.io/tredictpy)
