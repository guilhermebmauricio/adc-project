document.getElementById("darkToggle").addEventListener("click", function() {
    document.body.classList.toggle("dark");
    if (document.body.classList.contains("dark"))
        this.className = "bi bi-toggle-on";
    else
        this.className = "bi bi-toggle-off";
});