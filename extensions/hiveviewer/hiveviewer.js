if (postOptions['reset']){
    //clear the nodelist
    $('#nodelist ul').empty();
}

// Remove the parse button
$('#parsereg').remove();

// Prepare all the returned data.
var file_id = postOptions['file_id'];
var new_data = $.parseJSON(html_data);
var key_values = new_data['key_values'];
var child_keys = new_data['child_keys'];
var parent_key = decodeURIComponent(postOptions['key']);

// Friendly ID
parent_key = parent_key.replace(/\\/g, "_");



console.log("Parent Key = #"+parent_key);

// Add Nodes to Tree

$.each(child_keys, function( index, value ) {

    // Friendly ID
    var key_id = value.replace(/\\/g, "_");

    // If parent node exists then append to that.


    // If parent node exists
    if ( $("#"+parent_key ).length > 0) {
        console.log('Parent Node Exists');
        if ( $("#"+parent_key+"_Children" ).length < 1) {
             console.log('Child UL Needs Creating');
             $("#"+parent_key+ " label").after("<ul id='"+parent_key+"_Children'></ul>");
        }
        console.log('Appending Key');
        console.log('Here');
        $("#"+parent_key+"_Children").append("<li id='"+key_id+"'><input type=\"checkbox\" checked=\"checked\" id=\"item-"+index+"\" /><label for=\"item-"+index+"\" onclick=\"ajaxHandler('HiveViewer', {'file_id':'"+file_id+"', 'key': '"+encodeURIComponent(value)+"', 'reset': false, 'extension':true}, false )\">"+value+"</label>");



    // Else create new node

    } else {
        $('#nodelist ul').append("<li id='"+key_id+"'><input type=\"checkbox\" checked=\"checked\" id=\"item-"+index+"\" /><label for=\"item-"+index+"\" onclick=\"ajaxHandler('HiveViewer', {'file_id':'"+file_id+"', 'key': '"+encodeURIComponent(value)+"', 'reset': false, 'extension':true}, false )\">"+value+"</label>");
    }

});

// Populate Values
$('#regValues tbody').empty();
$.each(key_values, function( index, value ) {
  $('#regValues tbody').append('<tr><td>'+value[0]+'</td><td>'+value[1]+'</td><td>'+value[2]+'</td></tr>');
});

// End Reg