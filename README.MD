## Installs 
1. pip install cloudinary 
2. pip install Flask. Flask-sqlalchemy. Flask-Migrate. 

## Set up 
1. Have a cloudinary account to get api key, api secret and cloud name : set them up as environmental variables or in config file that will not be exposed.

## Migrations 
1. Python -m flask db init
2. Python -m flask db migrate -m ""
3. Python -m flask db upgrade

## Routes 
check app.py 

run app.py 