var form = document.getElementById('search')
var btn = document.getElementById('submitBtn')


form.addEventListener("submit", (e) => {
    e.preventDefault()
    if (document.getElementById('city').value) {
        window.location.replace(`${window.location.href.split("?")[0]}?city=${document.getElementById('city').value}`)
    }
})