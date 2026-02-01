import os
from databases import Database

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://strix_user:strix_password@localhost:5432/strix_pentesting")
database = Database(DATABASE_URL)
