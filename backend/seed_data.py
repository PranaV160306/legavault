import os
import sys

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.database import SessionLocal, Base, engine
from app.models import User, UserRole
from app.core.security import hash_password

def seed_users():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    
    test_users = [
        {
            "email": "lawyer@test.com",
            "full_name": "Advocate Rajesh Sharma (Senior Legal Counsel)",
            "role": "lawyer",
            "password": "LawyerPass123!"
        },
        {
            "email": "associate@test.com",
            "full_name": "Pooja Verma (Associate Attorney)",
            "role": "associate",
            "password": "AssociatePass123!"
        },
        {
            "email": "client@test.com",
            "full_name": "Vikram Malhotra (Client / Corporate Rep)",
            "role": "client",
            "password": "ClientPass123!"
        }
    ]
    
    print("\n[SEED] Initializing default test accounts for Objective 1...")
    for user_info in test_users:
        existing = db.query(User).filter(User.email == user_info["email"]).first()
        if not existing:
            u = User(
                email=user_info["email"],
                full_name=user_info["full_name"],
                role=user_info["role"],
                hashed_password=hash_password(user_info["password"]),
                is_active=True
            )
            db.add(u)
            print(f" [+] Created: {user_info['email']} | Role: {user_info['role']} | Pass: {user_info['password']}")
        else:
            print(f" [*] Exists : {user_info['email']} | Role: {user_info['role']}")
            
    db.commit()
    db.close()
    print("[SEED] Test accounts ready.\n")

if __name__ == "__main__":
    seed_users()
