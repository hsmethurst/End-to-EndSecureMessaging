import sys
import os 
from PIL import Image

''' Print out all the files available to send '''
def get_image():
    for image in os.listdir('images'):
        print(image)

''' Open the image '''
def open_image(filename):
    img = Image.open(f'images/{filename}')
    img.show()    

