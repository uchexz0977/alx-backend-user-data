from db import DB
from user import User  # Assuming User is defined in user module
import bcrypt  # For password hashing
import uuid
from sqlalchemy.orm.exc import NoResultFound

class Auth:
    def _hash_password(self, password: str) -> bytes:
        """
        Hashes a password using bcrypt's hashpw method.
        
        Args:
            password (str): The password string to be hashed.
            
        Return:
            bytes: The salted and hashed password.
        """
        # Generate a salt
        salt = bcrypt.gensalt()
        # Return the hashed password
        return bcrypt.hashpw(password.encode(), salt)

    def reset_token(self, email: str) -> str:
        """
        Generates a reset_token UUID for a user identified by the given email.
        
        Args:
            email (str): User's email address.
            
        Return:
            str: Newly generated reset_token for the relevant user.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError("No user found with the given email address.")

        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Updates a user's password.
        
        Args:
            reset_token (str): Reset_token issued to reset the password.
            password (str): User's new password.
            
        Return:
            None
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError("Invalid reset token.")

        hashed = self._hash_password(password)
        self._db.update_user(user.id, hashed_password=hashed, reset_token=None)


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        self._db = DB()

    def _hash_password(self, password: str) -> bytes:
        """
        Hashes a password using bcrypt's hashpw method.
        
        Args:
            password (str): The password string to be hashed.
            
        Return:
            bytes: The salted and hashed password.
        """
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode(), salt)

    def register_user(self, email: str, password: str) -> User:
        """
        Registers a new user with the given email and password.
        
        Args:
            email (str): The user's email address.
            password (str): The user's password.
        
        Return:
            User: The newly created User object.
        
        Raises:
            ValueError: If the user with the given email already exists.
        """
        try:
            # Check if the user already exists
            self._db.find_user_by(email=email)
            # If the user is found, raise ValueError
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            # If no user is found, create a new one
            hashed_password = self._hash_password(password)
            new_user = self._db.add_user(email=email, hashed_password=hashed_password)
            return new_user

class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        self._db = DB()

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validate the login credentials.

        Args:
            email (str): User's email address.
            password (str): User's password.

        Returns:
            bool: True if login is valid, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        # Check if the provided password matches the stored hashed password
        if bcrypt.checkpw(password.encode('utf-8'), user.hashed_password):
            return True
        else:
            return False

    def _generate_uuid() -> str:
        """
        Generate a new UUID and return its string representation.
    
        Returns:
        str: A new UUID as a string.
        """
        return str(uuid.uuid4())
    

class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        self._db = DB()

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validate the login credentials.

        Args:
            email (str): User's email address.
            password (str): User's password.

        Returns:
            bool: True if login is valid, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        # Check if the provided password matches the stored hashed password
        if bcrypt.checkpw(password.encode('utf-8'), user.hashed_password):
            return True
        else:
            return False

class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        self._db = DB()

    def get_user_from_session_id(self, session_id: Optional[str]) -> Optional[object]:
        """
        Returns a user object corresponding to a session ID.

        Args:
            session_id (str): The session ID string.

        Returns:
            Optional[object]: The user object if found, otherwise None.
        """
        if session_id is None:
            return None

        try:
            # Find the user by session ID
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            # If no user is found, return None
            return None

        return user
class Auth:
    def __init__(self, db):
        self._db = db

    def destroy_session(self, user_id: int):
        # Find the user by their user_id
        user = self._db.find_user_by_id(user_id)
        if user:
            # Update the user's session ID to None
            user.session_id = None
            # Save the updated user record
            self._db.save_user(user)
        else:
            # Handle the case where the user is not found
            raise ValueError("User not found")

# Assuming the database interface has methods like `find_user_by_id` and `save_user`


class Auth:
    def __init__(self, db):
        self._db = db

    def get_reset_password_token(self, email: str) -> str:
        # Find the user by email
        user = self._db.find_user_by_email(email)
        if user is None:
            # If the user does not exist, raise a ValueError
            raise ValueError("User not found")
        
        # Generate a new UUID for the reset token
        reset_token = str(uuid.uuid4())
        
        # Update the user's reset_token field
        user.reset_token = reset_token
        self._db.save_user(user)
        
        # Return the generated reset token
        return reset_token


class Auth:
    def __init__(self, db):
        self._db = db

    def _hash_password(self, password: str) -> str:
        # Hash the password using SHA-256 (consider using a stronger hashing method in practice)
        return hashlib.sha256(password.encode()).hexdigest()

    def update_password(self, reset_token: str, password: str) -> None:
        # Find the user by reset_token
        user = self._db.find_user_by_reset_token(reset_token)
        if user is None:
            # If the user does not exist, raise a ValueError
            raise ValueError("Invalid reset token")
        
        # Hash the new password
        hashed_password = self._hash_password(password)
        
        # Update the user's hashed_password and reset_token fields
        user.hashed_password = hashed_password
        user.reset_token = None
        self._db.save_user(user)

