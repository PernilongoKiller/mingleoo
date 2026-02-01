from app import Base, engine, app
from sqlalchemy import text

print("Resetting database...")
with app.app_context():
    # Explicitly drop tables with CASCADE to handle foreign key dependencies
    conn = engine.connect()
    trans = conn.begin()
    for table in reversed(Base.metadata.sorted_tables):
        conn.execute(text(f'DROP TABLE IF EXISTS "{table.name}" CASCADE;'))
    trans.commit()
    conn.close()

    Base.metadata.create_all(bind=engine)
print("Database reset.")