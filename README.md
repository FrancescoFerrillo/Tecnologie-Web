# 🌐🔒 PassBox 
Passbox is a locally hosted password manager web application designed for development and personal use only. The app is built using Flask (a Python micro-framework) and MongoDB and focuses on securely storing and organizing user credentials.  

# 📄 Proposal 
<a href="https://github.com/Francesco-Ferrillo/PassBox/blob/main/Proposal.pdf">
<p>Click For View The Proposal 📂<p>
</a>

# 🎥 Presentation
<a href="https://github.com/Francesco-Ferrillo/PassBox/blob/main/Presentation.pdf">
<p>Click For View The Presentation 📂<p>
</a>

⚙️ Technologies  
-------------------------
**Backend:** Python + Flask 🐍  
**Frontend:** HTML5, CSS, JavaScript 🎨  
**Database:** MongoDB for efficient and secure data management 💾  

# 🌐 Web Application
<a href="https://github.com/Francesco-Ferrillo/PassBox/blob/main/passbox.zip">
  <p>Click For Download PassBox 📥<p>
</a>

🎞️ Logo
-------------------------
<a href="https://github.com/Francesco-Ferrillo/PassBox/blob/main/passbox.zip">
<img src="Logo.png" alt="PassBox_Logo" width="200">
</a>


🔑 Key Features  
-------------------------
**Two-Factor Authentication (2FA):** The application supports 2FA with a master password that is encrypted on the database.  
**Vault Organization:** Users can create multiple vaults, each containing a set of credentials/accounts.  
**Each saved account includes:**  
        1. Passwords that are encrypted and stored securely in the database.  
        2. 2FA support, allowing users to store encrypted seeds for accounts with active 2FA.  
        3. An optional password expiration date for better security management.  
        4. Secure Backups: Users can export entire vaults into encrypted JSON files for safe backups.  
**⚠️ Important Note:** Passbox is a development application that works locally on your system. It is not designed to be deployed as a production-grade app, and its security features are intended for testing or personal use.  


🛠️ Setup Instructions  
-------------------------
Follow these steps to install and run the Passbox web application on your local machine.  


**1. Download the Project**  

Download the project ZIP file from the GitHub repository.  
Extract the ZIP file into a folder on your computer.  


**2. Install Python**  

Ensure that Python is installed on your system.  

Linux:  
Open a terminal and run:  
    sudo apt update  
    sudo apt install python3 python3-pip  

Windows:  
Download Python from the official Python website [Python](https://www.python.org/)  
During installation, ensure that you check the box to add Python to your PATH.  
Open Command Prompt (CMD) and verify the installation:  
    python --version  
    pip --version  


**3. Set Up a Virtual Environment**  

For better organization and dependency management, it’s recommended to use a virtual environment.  
Navigate to the directory of the downloaded project and execute the following commands:  

Linux:  
    python3 -m venv venv  
    source venv/bin/activate  

Windows:  
    python -m venv venv  
    venv\Scripts\activate  

In both cases, you should see (venv) at the beginning of your terminal prompt, indicating that the virtual environment is active.  


**4. Install Required Dependencies**  

With the virtual environment activated, install the required Python libraries using requirements.txt:  
pip install -r requirements.txt  


**5. Set Up the Database (MongoDB Atlas)**  

The app requires a MongoDB Atlas database:  

Visit the MongoDB Atlas website [MongoDB](https://www.mongodb.com/products/platform/atlas-database) and create a free account.  
    Set up a new cluster and create a database user with access credentials.  
    Obtain the connection string (URL) for your cluster. This will look something like:  

    mongodb+srv://<username>:<password>@cluster0.mongodb.net/<dbname>?retryWrites=true&w=majority  

    Replace <username>, <password>, and <dbname> with your database credentials.  


**6. Set Up PayPal Sandbox for Donations**  

To enable donation functionality, you need to configure PayPal Sandbox:  
    Visit the PayPal Developer Sandbox [PayPal](https://developer.paypal.com/home/)  and sign up for a developer account.  
    Create a sandbox business account.  
    Generate API credentials (Client ID and Secret) for your app.  
    Save the Client ID and Secret values for the next step.  


**7. Configure the .env File**  

The application requires environment variables for MongoDB and PayPal.  

Open the .env file and fill in the following fields:  
    PAYPAL_CLIENT_ID – Your PayPal Sandbox Client ID.  
    PAYPAL_SECRET – Your PayPal Sandbox Secret.  
    MONGODB_URL – The MongoDB Atlas connection string.  

Rename the .env_example file to .env.  

Example .env file:  
    PAYPAL_CLIENT_ID=your-paypal-client-id  
    PAYPAL_SECRET=your-paypal-secret  
    MONGODB_URL=your-mongodb-url  


**8. Run the Application**  

Open a terminal, navigate to the project folder, and ensure the virtual environment is activated.  

Run the application:  
python app.py  

Open your browser and navigate to:  
http://localhost:5000   

