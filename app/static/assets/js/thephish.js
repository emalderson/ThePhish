// Obtain HTML DOM elements
let desc_div = document.getElementById("descDiv");
let div_data_table = document.getElementById("divDataTable");
let data_table = document.getElementById("dataTable");
let list_mails_btn = document.getElementById("listMailsBtn");
let progress_bar = document.getElementById("progressBar");
let card_header = document.getElementById("cardHeader");
let div_result = document.getElementById("divResult");
let card_body_table_res = document.getElementById("cardBodyTableRes");
let go_back_link = document.getElementById("goBackLink");
let log_text = document.getElementById("logText");
let log_text_par = log_text.getElementsByTagName("p")[0]


// Obtain the socket object
// Automatically start a connection to window.location
const socket = io();

// Enable the "List emails" button once the connection is established and the SID is available
socket.on("connect", () => {
	list_mails_btn.classList.remove("disabled");
});

// Modify the DOM to append the received message and scroll the div
socket.on("logInfo", data => {
	log_text_par.innerHTML += "[INFO]: " + data + "<br/>";
	updateScroll();
});

socket.on("logWarning", data => {
	log_text_par.innerHTML += "[WARNING]: " + data + "<br/>";
	updateScroll();
});

socket.on("logError", data => {
	log_text_par.innerHTML += "[ERROR]: " + data + "<br/>";
	updateScroll();
});

// Function that automatically scrolls the div when new logs are appended to it
function updateScroll(){
	log_text_par.parentNode.scrollTop = log_text_par.parentNode.scrollHeight;
}

// Function used to show an error or warning alert
function showAlert(type){
	let alert = document.createElement("div");
	alert.setAttribute("role", "alert");
	if(type === "error"){
		alert.setAttribute("class", "alert alert-danger alert-dismissible");
	} else if (type === "warning") {
		alert.setAttribute("class", "alert alert-warning alert-dismissible");
	}
	alert.setAttribute("style", "text-align: left;margin-top: 15px;margin-bottom: 0px;");
	let close = document.createElement("Button");
	close.setAttribute("type", "button");
	close.setAttribute("class", "btn-close");
	if(type === "error"){
		close.setAttribute("onclick", "window.location.reload()");
	}
	close.setAttribute("data-bs-dismiss", "alert");
	close.setAttribute("aria-label", "Close");
	alert.appendChild(close);
	let span = document.createElement("span");
	if(type === "error"){
		span.innerHTML="<strong>An error has occurred.</strong>";
	} else if (type === "warning") {
		span.innerHTML="<strong>There are no e-mails to read.</strong>";
	}
	alert.appendChild(span);
	document.getElementById("cardHeader").appendChild(alert);
}

// Function called when the "List emails" button is clicked
function list_emails(){
	// Modify the DOM to show the progress bar
	data_table.tBodies[0].innerHTML="";
	div_data_table.classList.add("d-none");
	list_mails_btn.classList.add("d-none");
	progress_bar.classList.remove("d-none");
	progress_bar.firstElementChild.classList.add("progress-bar-animated");
	progress_bar.firstElementChild.innerHTML = "<strong>Retrieving emails...</strong>";
	// Prepare the AJAX GET request to the path /list
	let xhr = new XMLHttpRequest();
	xhr.open('GET', 'list', true);
	// Function called when the response is available
	xhr.onreadystatechange = function() {
		if(xhr.readyState == 4) {
			if(xhr.status == 200) {
				let response = JSON.parse(xhr.responseText);
				if (response == null){	  
					// Handle errors during the execution	   
					showAlert("error");
					progress_bar.firstElementChild.classList.remove("bg-info");
					progress_bar.firstElementChild.classList.add("bg-danger");
					progress_bar.firstElementChild.classList.remove("progress-bar-animated");
					progress_bar.firstElementChild.innerHTML="<strong>Error</strong>";
				} else if(response.length == 0){
					// Handle empty list of emails
					showAlert("warning");
					list_mails_btn.classList.remove("d-none");
					progress_bar.classList.add("d-none");
					progress_bar.firstElementChild.classList.remove("progress-bar-animated");
				} else {
					// Modify DOM to add the emails to a table
					for(element of response){
						let row = document.createElement("tr");
						let td_uid = document.createElement("td"); 
						td_uid.appendChild(document.createTextNode(element.mailUID));
						row.appendChild(td_uid);
						let td_date = document.createElement("td"); 
						td_date.appendChild(document.createTextNode(element.date));
						row.appendChild(td_date); 
						let td_from = document.createElement("td"); 
						td_from.appendChild(document.createTextNode(element.from));
						row.appendChild(td_from); 
						let td_subject = document.createElement("td"); 
						td_subject.appendChild(document.createTextNode(element.subject));
						row.appendChild(td_subject);
						let td_body = document.createElement("td"); 
						td_body.appendChild(document.createTextNode(element.body));  
						row.appendChild(td_body); 
						let td_attachment = document.createElement("td"); 
						td_attachment.appendChild(document.createTextNode(element.attachedMail));
						row.appendChild(td_attachment); 
						let td_button = document.createElement("td"); 
						td_button.setAttribute("class", "justify-content-xl-end");
						let button = document.createElement("button");
						button.setAttribute("class", "btn btn-primary border rounded");
						button.setAttribute("type", "button");
						button.setAttribute("style", "background: rgb(40,106,149);font-size: 20px;");
						button.setAttribute("onclick", "analyze_email(this)");
						button.appendChild(document.createTextNode("Analyze"));
						td_button.appendChild(button);
						row.appendChild(td_button);   

						data_table.tBodies[0].appendChild(row);
						desc_div.classList.add("d-none");
						div_data_table.classList.remove("d-none");
						
						list_mails_btn.classList.remove("d-none");
						progress_bar.classList.add("d-none");
						progress_bar.firstElementChild.classList.remove("progress-bar-animated");
					}
				}
			}
			else {
				// Handle errors during the execution
				showAlert("error");
				progress_bar.firstElementChild.classList.remove("bg-info");
				progress_bar.firstElementChild.classList.add("bg-danger");
				progress_bar.firstElementChild.classList.remove("progress-bar-animated");
				progress_bar.firstElementChild.innerHTML="<strong>Error</strong>";
			}
		}
	}
	// Send the request
	xhr.send(null);
}


// Function called when the "Analyze" button is clicked for an email
// The button node is used to obtain the index of the table row on which the button has been clicked
function analyze_email(thisBtn){

	let index = thisBtn.parentNode.parentNode.rowIndex;
	let uid_field = data_table.tBodies[0].rows[index-1].cells[0].innerHTML;
	
	// Modify the DOM to show the progress bar and the div used to show the logs
	list_mails_btn.classList.add("d-none");
	div_data_table.classList.add("d-none");
	progress_bar.classList.remove("d-none");
	progress_bar.firstElementChild.classList.add("progress-bar-animated");
	progress_bar.firstElementChild.innerHTML = "<strong>Analyzing...</strong>";
	log_text.classList.remove("d-none")
	// Prepare the AJAX POST request to the path /analysis
	let xhr = new XMLHttpRequest();
	xhr.open('POST', 'analysis', true);
	xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
	// Function called when the response is available
	xhr.onreadystatechange = function() {
		if(xhr.readyState == 4) {
			if(xhr.status == 200) {
				let response = JSON.parse(xhr.responseText);
				if (response == null){
					// Handle errors during the execution
					showAlert("error");
					progress_bar.firstElementChild.classList.remove("bg-info");
					progress_bar.firstElementChild.classList.add("bg-danger");
					progress_bar.firstElementChild.classList.remove("progress-bar-animated");
					progress_bar.firstElementChild.innerHTML="<strong>Error</strong>";
				} else {
					// Modify the DOM to show the result
					card_body_table_res.classList.remove("d-none");
					progress_bar.firstElementChild.classList.remove("bg-info");
					progress_bar.firstElementChild.classList.add("bg-success");
					progress_bar.firstElementChild.classList.remove("progress-bar-animated");
					progress_bar.firstElementChild.innerHTML="<strong>Success</strong>";
					go_back_link.classList.remove("d-none");
					if (response == "Safe"){
						div_result.getElementsByTagName("p")[0].style.background="rgba(0,166,90,255)";
						div_result.getElementsByTagName("p")[0].innerHTML="<strong>SAFE</strong>";
						div_result.getElementsByTagName("p")[1].innerHTML="<br/>The e-mail has been classified as SAFE. The case has been closed and the response has been sent.<br/>";
					} else if (response == "Malicious"){
						div_result.getElementsByTagName("p")[0].style.background="rgb(221,75,57)";
						div_result.getElementsByTagName("p")[0].innerHTML="<strong>MALICIOUS</strong>";
						div_result.getElementsByTagName("p")[1].innerHTML="<br/>The e-mail has been classified as MALICIOUS. The case has been closed, the submission on MISP has been made and the response has been sent.<br/>";
					} else if (response == "Suspicious"){
						div_result.getElementsByTagName("p")[0].style.background="rgb(255,212,37)";
						div_result.getElementsByTagName("p")[0].innerHTML="<strong>SUSPICIOUS</strong>";
						div_result.getElementsByTagName("p")[1].innerHTML="<br/>The e-mail has been classified as SUSPICIOUS. The case has been left open for further investigation. Please use the buttons on the left to review the result of the analysis, close the case and send a response.<br/>";
					}
					div_result.classList.remove("d-none");
				}
			}
			else {
				// Handle errors during the execution
				showAlert("error");
				progress_bar.firstElementChild.classList.remove("bg-info");
				progress_bar.firstElementChild.classList.add("bg-danger");
				progress_bar.firstElementChild.classList.remove("progress-bar-animated");
				progress_bar.firstElementChild.innerHTML="<strong>Error</strong>";
			}
		}
	};
	// Send the request with the SID and the UID of the email
	xhr.send("sid=" + socket.id + "&mailUID=" + uid_field);
} 