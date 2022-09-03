# aura_tech_inter
Hello there! This my project as presented to you. I've devided the code to multiple files then to assembled all toghether and run as a single file in the RAM instead of using the importing which is much faster as useful approach.
<br>
<br>
It have 'src/base.py' file that contains all necessary classes to store variables and functions as static to prevent any code confusion or clash. Each class have its own static functions and variables depending on its role in the app and they are well named and sef-explanatory I guess so I didnt put much comments there.
<br>
<br>
the "models" folder contains the users's admin/editor views and a secure form with CSRF token auto-generated and auto-validated.
<br>
<br>
The "urls" folder contains files each represents a site functionality and view:
<br>urls/login.py ==> /login && /login/
<br>urls/register.py ==> /register && /register/
<br>urls/show-user-profile/{user_id} ==> /show-user-profile/<user_id> && /show-user-profile/<user_id>/
<br>...
<br>this will make adding / editing / fixing and deleting functionalities and views much easier and safer !

<br>
<br>
also there is an predefined and customizable secure admin panel with all necessary functionalities of the CRUD and session/permissions management with 2 access level: super admin and an editor with less permissions and access to the data.

# best practices applied:

<ul>
  <li>using google recaptcha to prevent: brute force attacks and bots that tries to create accounts.</li>
  <li>CSRF protection in both admin forms and user forms.</li>
  <li>checking the existance for the email before registering or updating user data.</li>
  <li>checking file extensions and content types to prevent uploading any malicious file.</li>
  <li>storing the passwords in non-plaintext format (hashes).</li>
  <li>redirecting the user/admin when accessing any page that allow higher or different access level.</li>
  <li>diny non authenticated persons from viewing pages that requires authentication.</li>
  <li>storing user session data and admin session data each in a seperated session variables to prevent any confusion.</li>
  <li>instead of using login manager, I created a specific class to manage the session and other to validate it. The login manager doesn't have an expiration date for the session which is not practcal because the session must have a lifespan that can't be passed, also every time it is called it will connect to the database and with many users, this will slow down the application! So, when starting any user/admin session I add a variable indicating when the session started and when the current_time - session_start_time passes the duration of the session's lifespan then it's no longer valid. And about the aproach of loading user's data, on login I store all user's data in the session and if any update happens then I update the updated values, thus, putting less pressure on the database.</li>
</ul>
