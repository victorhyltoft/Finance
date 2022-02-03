# Finance
A finance website making it possible for individual users to buy and sell stock shares using an external REST API to get current stock prices. 
This project is built using Flask including jinja2 for the front-end and SQLite for the backend. 
The app among other things, demonstrates user authentication, API CRUD operations, database structuring and querying using SQL.

The SQL database consists of two tables; "users" and "user_shares". 
The users table contains information about the UUID, username, the password (hashed) and the balance. 
The "user_shares" has the following columns; UUID (the specific user's stock), (stock) symbol, (stock) name, (number of) shares, (bought) price and time (bought).

## Get started
You'll need your own API-key and have to save it as an environment variable called "API_KEY" to run the project.  
Obtain an API key from [iexcloud.io](https://iexcloud.io/docs/api/) to get started.

Download the requirements from the requirements.txt using pip; <code>pip install -r requirements.txt</code>
