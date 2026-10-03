// Settings popup — uses localStorage (same origin as background page in MV2)

function saveOptions(e) {
    e.preventDefault();
    localStorage.setItem("host", document.querySelector("#host").value);
    localStorage.setItem("port", document.querySelector("#port").value);
    localStorage.setItem("enabled", document.querySelector("#enabled").checked);
    document.querySelector("#status-success").classList.remove("hide");
    setTimeout(function () {
        document.querySelector("#status-success").classList.add("hide");
    }, 3000);
}

function restoreOptions() {
    document.querySelector("#host").value = localStorage.getItem("host") || "localhost";
    document.querySelector("#port").value = localStorage.getItem("port") || 8889;
    document.querySelector("#enabled").checked = localStorage.getItem("enabled") === "true";
}

document.addEventListener("DOMContentLoaded", restoreOptions);
document.querySelector("form").addEventListener("submit", saveOptions);
