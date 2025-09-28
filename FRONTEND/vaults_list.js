function openModal(id) {
    const modal = document.getElementById("modal-" + id);
    modal.style.display = "block";
}

function closeModal(id) {
    const modal = document.getElementById(`modal-${id}`);
    modal.style.display = "none";
}

function confirmDelete(url) {
    if (confirm("Are you sure you want to eliminate this vault?")) {
        window.location.href = url;
    }
}

document.addEventListener("DOMContentLoaded", function () {
    const container = document.getElementById("animated");
    container.classList.add("show"); 
});

document.addEventListener("DOMContentLoaded", function () {
    const container = document.getElementById("animated2");
    container.classList.add("show"); 
});



document.addEventListener("DOMContentLoaded", function () {
    const items = document.querySelectorAll(".credential-item");

    items.forEach((item, index) => {
        setTimeout(() => {
            item.classList.add("popup-animation");
        }, index * 100); 
    });
});



