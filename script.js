document.addEventListener("DOMContentLoaded", function() {
    const container = document.querySelector(".container");
    container.style.opacity = 1;
    container.style.transform = "translateY(0)";

    const music = document.getElementById("bg-music");
    const toggleMusic = document.getElementById("toggle-music");

    music.play();

    toggleMusic.addEventListener("click", function() {
        if (music.paused) {
            music.play();
            toggleMusic.textContent = "⏸ Pause";
        } else {
            music.pause();
            toggleMusic.textContent = "🎵 Play";
        }
    });
});
