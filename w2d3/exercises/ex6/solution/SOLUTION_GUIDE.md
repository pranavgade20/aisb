Download any game state and save it as test.pkl 
```python

import pickle
with open("test.pkl", "rb") as f:
    s = f.read()
a = pickle.loads(s)
a['apple_size'] = 10000
with open("ch.pkl", "wb") as f:
    pickle.dump(a,f)
```