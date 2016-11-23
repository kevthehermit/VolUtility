if (postOptions['reset']){
    //clear the nodelist
    // The shell has been reset so clear the output and restore the VolShell start button

}
// Remove the volstart button
$('#volstart').remove();
//console.log(html_data);

// Append results to the window
$('#volshell-out').append(html_data);

// Scroll to bottom
$('#volshell-out').scrollTop(1E10);


// End Reg