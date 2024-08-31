from app import app, db

# create database tables using models
with app.app_context():
    db.create_all()

print("Tables created succesfully!")
