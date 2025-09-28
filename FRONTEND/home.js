function isElementInViewport(el) {
    const rect = el.getBoundingClientRect();
    return (rect.top >= 0 && rect.left >= 0 && rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) && rect.right <= (window.innerWidth || document.documentElement.clientWidth));
}

function handleScroll() {
    const elements = document.querySelectorAll('.scroll-animate');
    
    elements.forEach(element => {
        if (isElementInViewport(element)) {
            element.classList.add('visible');
        }
    });
}

window.addEventListener('scroll', handleScroll);

document.addEventListener('DOMContentLoaded', handleScroll);

window.onload = function () {
    const profileButton = document.querySelector(".open-menu-button");
    profileButton.classList.add("animate"); 
};

window.onload = function () {
    const profileButton = document.querySelector(".open-menu-button");
    profileButton.classList.add("animate"); 
};

function isInViewport(element) {
    const rect = element.getBoundingClientRect();
    return (
        rect.top >= 0 &&
        rect.left >= 0 &&
        rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
        rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
}

document.addEventListener("scroll", () => {
    const coverSection = document.getElementById("cover-section");
    
    if (isInViewport(coverSection)) {
        coverSection.classList.add("visible");
    }

});

function isElementInViewport(el) {
    const rect = el.getBoundingClientRect();
    return rect.top >= 0 && rect.left >= 0 && rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) && rect.right <= (window.innerWidth || document.documentElement.clientWidth);
}

window.addEventListener('scroll', function() {
    const gridElements = document.querySelectorAll('.gridBlur');
    
    gridElements.forEach(function(element) {
    if (isElementInViewport(element)) {
        element.classList.add('visible'); 
    } 
    });
});


function openModal(id) {
    const modal = document.getElementById("modal-" + id);
    if (modal) {
        modal.style.display = "block";
    }
}

function closeModal(id) {
    const modal = document.getElementById("modal-" + id);
    if (modal) {
        modal.style.display = "none";
    }
}

document.addEventListener("DOMContentLoaded", function () {
    const closeButtons = document.querySelectorAll(".close");
    closeButtons.forEach(button => {
        button.addEventListener("click", function () {
            const modalId = button.closest(".modal").id.split("-")[1];
            closeModal(modalId);
        });
    });
});

function toggleEditable() {
    const fields = ['username', 'email', 'password'];
    const toggleButton = document.getElementById('toggle-button');
    const isCurrentlyLocked = toggleButton.classList.contains('locked');

    fields.forEach(fields => {
        const field = document.getElementById(fields);
        field.disabled = isCurrentlyLocked;
    });

    if (isCurrentlyLocked) {
        toggleButton.textContent = 'Unlock';
        toggleButton.classList.remove('locked');
    } else {
        toggleButton.textContent = 'Lock';
        toggleButton.classList.add('locked');
    }
}

function validateSubmit(url) {
    const toggleButton = document.getElementById('toggle-button');

    if (!toggleButton.classList.contains('locked')) {
        alert('You have to unlock the fields before you can save the changes!');
        return false;
    }

    return confirmEdit(url);
}

function confirmEdit(url) {
    if (confirm("Are you sure you want to change these credentials?")) {
        window.location.href = url;
    }
}

