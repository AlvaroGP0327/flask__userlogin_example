# Documentation

##Register-Function
**Location**: `@app.route('/register', methods=['GET', 'POST'])`
### Description
Handles user registration.

### Algorithm
1. Create an instance of `RegisterForm`.
2. Check if the form is validated on submission.
3. If valid, create a new user instance with the form data.
4. Add the user to the database session.
5. Commit the session to save the user.
6. Flash a success message.
7. Redirect the user to the login page.