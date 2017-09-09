$(document).ready(function(){

	$('ul.tabs li').click(function(){
		var tab_id = $(this).attr('data-tab');

		$('ul.tabs li').removeClass('current');
		$('.tab-content').removeClass('current');

		$(this).addClass('current');
		$("#"+tab_id).addClass('current');
	})

})

function validateForm() {
    var x = document.forms["login"]["username"].value;
    var y = document.forms["login"]["password"].value;
    if (x == "") {
        alert("Username must be filled out");
        return false;
    }
    if (y == "") {
        alert("Password must be filled out");
        return false;
    }
}

function validateForm2() {
    var x = document.forms["login2"]["username"].value;
    var y = document.forms["login2"]["password"].value;
    var z = document.forms["login2"]["password2"].value;
    var a = document.forms["login2"]["email"].value;
    if (x == "") {
        alert("Username must be filled out");
        return false;
    }
    if (y == "") {
        alert("Password must be filled out");
        return false;
    }
    if (z == "") {
        alert("Password confirm must be filled out");
        return false;
    }
    if (a == "") {
        alert("Email must be filled out");
        return false;
    }
    if (z!=y){
        alert("Passwords must match");
        return false;
    }
}
