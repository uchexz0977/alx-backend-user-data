class Auth:
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

        hashed = _hash_password(password)
        self._db.update_user(user.id, hashed_password=hashed, reset_token=None)

