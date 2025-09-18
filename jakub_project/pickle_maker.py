# %%
import pickle
import pickletools
import numpy as np

obj = {'A': 'Colliding objects can be of different lengths, types, etc.'}
# obj = 666
# obj = [1, 2, (3, 4), {b'abc': "def"}]
# obj = np.random.rand(5, 5)

data = pickle.dumps(obj, protocol=4)
pickletools.dis(data)

with open("example2_in1.pkl", "wb") as f:
    f.write(data)

