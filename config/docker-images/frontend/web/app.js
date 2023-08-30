fetch('http://localhost:8888/')
.then(function (response) {
	return response.json();
})
.then(function (json) {
    document.querySelector("#msg").innerHTML = json.msg;
    document.querySelector("#lang").innerHTML = '<i>-' + json.language + '</i>';
    
    fetch('http://localhost:8336/send_log', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(json)
    })
    .then(response => response.json())
    .then(data => console.log('Response from Python:', data))
    .catch(error => {
        console.error('Error sending data to Python:', error);
    });
})
.catch(error => {
    console.log("Fetching trees data failed", error);
});

