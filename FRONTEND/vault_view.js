
function openModal(id) {
    const modal = document.getElementById(`modal-${id}`);
    if (modal) {
        modal.style.display = "block";
    }
}

function closeModal(id) {
    const modal = document.getElementById(`modal-${id}`);
    if (modal) {
        modal.style.display = "none";
    } 
}

function toggleEditable(id) {
    const fields = ['title', 'username', 'email', 'password', 'url', 'category'];
    const toggleButton = document.getElementById(`lock-button-${id}`);
    const isCurrentlyLocked = toggleButton.classList.contains('locked');

    fields.forEach(fieldName => {
        const field = document.getElementById(`${fieldName}-${id}`);
        if (field) {
            field.disabled = isCurrentlyLocked;
        }
    });

    if (isCurrentlyLocked) {
        toggleButton.textContent = 'Unlock';
        toggleButton.classList.remove('locked');
    } else {
        toggleButton.textContent = 'Lock';
        toggleButton.classList.add('locked');
    }
}

function validateSubmit(id, url) {
    const lockButton = document.getElementById(`lock-button-${id}`);

    if (!lockButton.classList.contains('locked')) {
        alert('You have to unlock the fields before you can save the changes!');
        return false;
    }

    return confirmEdit(url)
}


function togglePassword(credentialId, encryptedPassword) {
    const passwordField = document.getElementById(`password-${credentialId}`);
    const toggleButton = document.getElementById(`toggle-button-password-${credentialId}`);

    if (passwordField.type === 'password') {
        fetch('/data', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ encrypted_field: encryptedPassword })
        })
            .then(response => response.json())
            .then(data => {
                console.log("Server response:", data);
                if (data.decrypted_field) {
                    passwordField.type = 'text';
                    passwordField.value = data.decrypted_field;
                    toggleButton.innerText = 'Hide';
                } else {
                    console.error("Error in decoding the password.");
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('An error occurred in loading the password.');
            });
    } else {
        passwordField.type = 'password';
        passwordField.value = '********';
        toggleButton.innerText = 'Show';
    }
}

function toggleSeed(credentialId, encryptedSeed) {
    const seedField = document.getElementById(`seed-${credentialId}`);
    const toggleButton = document.getElementById(`toggle-button-seed-${credentialId}`);

    if (seedField.type === 'password') {
        fetch('/data', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ encrypted_field: encryptedSeed })
        })
            .then(response => response.json())
            .then(data => {
                console.log("Server response:", data);
                if (data.decrypted_field) {
                    seedField.type = 'text';
                    seedField.value = data.decrypted_field;
                    toggleButton.innerText = 'Hide';
                } else {
                    console.error("Error in decoding the seed.");
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('An error occurred in loading the seed.');
            });
    } else {
        seedField.type = 'password';
        seedField.value = '********';
        toggleButton.innerText = 'Show';
    }
}

function copyPassword(credentialId, encryptedPassword) {
    const passwordField = document.getElementById(`password-${credentialId}`);
    const passwordToCopy = passwordField.type === 'password' ? encryptedPassword : passwordField.value;
    navigator.clipboard.writeText(passwordToCopy)
        .then(() => console.log("Password copied to clipboard."))
        .catch(error => console.error("Error copying password", error));
}

function copySeed(credentialId, encryptedSeed) {
    const seedField = document.getElementById(`seed-${credentialId}`);
    const seedToCopy = seedField.type === 'password' ? encryptedSeed : seedField.value;
    navigator.clipboard.writeText(seedToCopy)
        .then(() => console.log("Seed copied to clipboard."))
        .catch(error => console.error("Error copying:", error));
}

function fetchOTP(id, collectionName) {
    const seedInput = document.getElementById(`seed-${id}`);
    const qrCodeImg = document.getElementById(`qr-code-${id}`);
    const otpDisplay = document.getElementById(`otp-${id}`);
    const timerDisplay = document.getElementById(`timer-${id}`);

    if (!seedInput.value) {
        alert("Enter a valid seed!");
        return;
    }

    fetch('/generate_otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            seed: seedInput.value,
            coll_name: collectionName,
            cred_id: id
        })
    })
        .then(response => response.json())
        .then(data => {
            console.log("Backend response:", data);
            if (data.error) {
                alert(data.error);
                return;
            }

            if (data.qr_url) {
                qrCodeImg.src = `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(data.qr_url)}&size=150x150`;
                qrCodeImg.style.display = "block";
            }

            otpDisplay.textContent = data.otp;
            let timeRemaining = data.time_remaining;
            const interval = setInterval(() => {
                if (timeRemaining <= 0) {
                    clearInterval(interval);
                    timerDisplay.textContent = "Code Expired!";
                    timerDisplay.style.color = "red";
                } else {
                    timerDisplay.textContent = `${timeRemaining}s`;
                    timerDisplay.style.color = timeRemaining <= 5 ? "red" : "black";
                    timeRemaining--;
                }
            }, 1000);
        })
        .catch(error => console.error("Errore: ", error));
}

function updateExpirationDate(credentialId) {
    const expirationDate = document.getElementById("expiration-date-" + credentialId).value;
    const expirationElement = document.getElementById("expiration-" + credentialId);
    const expirationWarning = document.getElementById("expiration-warning-" + credentialId);
    const icon = document.getElementById("calendar-icon-" + credentialId);

   if (isDateExpired(expirationDate)) {
       expirationElement.style.backgroundColor = "red";  
       expirationWarning.style.display = "block";       
       icon.classList.add("expired");                   
       icon.title = "The password has expired!";           
   } else {
       expirationElement.style.backgroundColor = "transparent"; 
       expirationWarning.style.display = "none";               
       icon.classList.remove("expired");                        
       icon.title = "Set Due Date";                         
   }
}

 function isDateExpired(expirationDate) {
     const currentDate = new Date();
     const expirationDateObj = new Date(expirationDate);
    return expirationDate && expirationDateObj < currentDate;
 }

 function initializeExpirationWarnings(credentialId) {
   const expirationDate = document.getElementById("expiration-date-" + credentialId).value;
   if (expirationDate) {
       updateExpirationDate(credentialId);
   }
}

function filterCredentials() {
    const searchQuery = document.getElementById("search").value.toLowerCase();
    const credentialItems = document.querySelectorAll(".credential-item");

    credentialItems.forEach(item => {
        const title = item.querySelector(".title").textContent.toLowerCase();
        const username = item.querySelector(".username").textContent.toLowerCase();
        const email = item.querySelector(".email").textContent.toLowerCase();
        const category = item.querySelector(".category").textContent.toLowerCase();

        if (title.includes(searchQuery) || username.includes(searchQuery) || email.includes(searchQuery) || category.includes(searchQuery)) {
            item.style.display = "block";
        } else {
            item.style.display = "none";
        }
    });
}

function confirmDelete(url) {
    if (confirm("Are you sure you want to delete these credentials?")) {
        window.location.href = url;
    }
}

function confirmEdit(url) {
    if (confirm("Are you sure you want to change these credentials?")) {
        window.location.href = url;
    }
}

function generateStrongPassword() {
    const length = 16;
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+[]{}|;:,.<>?";
    let password = "";
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        password += charset[randomIndex];
    }
    return password;
}

function suggestPassword(fieldId) {
    const generatedPassword = generateStrongPassword();
    const passwordField = document.getElementById(`password-${fieldId}`);
    passwordField.value = generatedPassword;
    passwordField.type = "text";
}

document.addEventListener("DOMContentLoaded", function () {
    const items = document.querySelectorAll(".credential-item");

    items.forEach((item, index) => {
        
        setTimeout(() => {
            item.classList.add("popup-animation");
        }, index * 100); 
    });
});

document.addEventListener("DOMContentLoaded", function () {
    const items = document.querySelectorAll(".container");

    items.forEach((item, index) => {
        setTimeout(() => {
            item.classList.add("popup-animation");
        }, index * 100); 
    });
});

document.addEventListener("DOMContentLoaded", function () {
    const searchBar = document.querySelector(".search-bar");
    setTimeout(() => {
        searchBar.classList.add("fade-in-animation");
    }, 200); 
});

document.addEventListener("DOMContentLoaded", function () {
    const backButtons = document.querySelectorAll(".back-button");

    backButtons.forEach((button, index) => {
       
        setTimeout(() => {
            button.classList.add("fade-slide-up");
        }, index * 150); 
    });
});

function generatePassword(level) {
    let chars = "";
    if (level === "easy") {
        chars = "abcdefghijklmnopqrstuvwxyz";
    } else if (level === "medium") {
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    } else if (level === "hard") {
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+[]{}|;:,.<>?";
    }

    const passwordLength = level === "easy" ? 12 : level === "medium" ? 16 : 18;
    let password = "";

    for (let i = 0; i < passwordLength; i++) {
        const randomIndex = Math.floor(crypto.getRandomValues(new Uint32Array(1))[0] / (0xFFFFFFFF + 1) * chars.length);
        password += chars[randomIndex];
    }

    const output = document.getElementById("output");
    output.textContent = password;
}

document.addEventListener("DOMContentLoaded", function () {
    const container = document.querySelector(".container2");

    setTimeout(() => {
        container.classList.add("slide-up-animation");
    }, 200);
});