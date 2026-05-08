import numpy as np
from PIL import Image

enc1 = Image.open("flag_enc.png")
enc2 = Image.open("notflag_enc.png")

enc1np = np.array(enc1)
enc2np = np.array(enc2)

result_np = np.bitwise_xor(enc1np, enc2np).astype(np.uint8)
Image.fromarray(result_np).save('flag_visibile.png')
