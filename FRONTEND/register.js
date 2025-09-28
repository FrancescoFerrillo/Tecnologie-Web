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
    const passwordField = document.getElementById(fieldId);
    passwordField.value = generatedPassword;
    passwordField.type = "text";
}


function togglePasswordVisibility(className) {
    const passwordFields = document.getElementsByClassName(className);
    
    for (let i = 0; i < passwordFields.length; i++) {
        const field = passwordFields[i];
        field.type = field.type === "password" ? "text" : "password";
    }
}

document.addEventListener("DOMContentLoaded", function () {
    const popupContainer = document.getElementById("popup-container");
    popupContainer.classList.add("show"); 
});
