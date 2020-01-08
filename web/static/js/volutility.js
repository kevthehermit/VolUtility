/**
 * Part of VolUtility
 */



function sessionCreate() {
    //jQuery.noConflict();
    $('#sessionModal').modal('hide');
    spinnerControl('open', 'Preparing your image for analysis');
}

$.ajaxTransport("+binary", function(options, originalOptions, jqXHR){
    // check for conditions and support for blob / arraybuffer response type
  if (window.FormData && ((options.dataType && (options.dataType == 'binary')) ||
                          (options.data && ((window.ArrayBuffer && options.data instanceof ArrayBuffer) ||
                                            (window.Blob && options.data instanceof Blob)))))
    {
        return {
            // create new XMLHttpRequest
            send: function(headers, callback){
		// setup all variables
                var xhr = new XMLHttpRequest(),
		url = options.url,
		type = options.type,
		async = options.async || true,
		// blob or arraybuffer. Default is blob
		dataType = options.responseType || "blob",
		data = options.data || null,
		username = options.username || null,
		password = options.password || null;
                xhr.addEventListener('load', function(){
			var data = {};
			data[options.dataType] = xhr.response;
			// make callback and send data
			callback(xhr.status, xhr.statusText, data, xhr.getAllResponseHeaders());
                });
                xhr.open(type, url, async, username, password);
		// setup custom headers
		for (var i in headers ) {
			xhr.setRequestHeader(i, headers[i] );
		}
                xhr.responseType = dataType;
                xhr.send(data);
            },
            abort: function(){
                jqXHR.abort();
            }
        };
    }
});


// New Stuff Starts Here =========================================================================== //

/*
Download to file
Single Function to handle file downloads.

Params:
    command: str = name of command
    postFields: str(json) = json string of POST options
    spinner: Bool = Overlay a loading spinner or not.'
 */


/*
Plugin Table Filter:
Just a simple table filter

 */
$(document).ready(function() {

    (function($) {

        $('#pluginfilter').keyup(function() {

            var rex = new RegExp($(this).val(), 'i');
            $('.pluginsearch tr').hide();
            $('.pluginsearch tr').filter(function() {
                return rex.test($(this).text());
            }).show();

        })

    }(jQuery));

});

/*
SpinnerControl opens and closes the loading page
Not many plugins need to use this.

 */

function spinnerControl(state, message){
    if (state == 'open'){
        document.getElementById('loadingtext').innerHTML = message;
       document.getElementById("spinnerdiv").style.width = "100%";
    } else {
        document.getElementById("spinnerdiv").style.width = "0%";
    }
}


/*
Alert Bar:
Generates a dismissable alert bar at the top of tha page.
Params:
    alertType: str = success or warning or danger or info
    strong: str = text in BOLD
    message: str = remainder of message

 */

function alertBar(alertType, strong, message){
    var alert_bar = '<div id="alert-bar" class="alert alert-' + alertType + ' alert-dismissible fade in text-center" role="alert"> \
                           <button type="button" class="close" data-dismiss="alert" aria-label="Close">\
                           <span aria-hidden="true">&times;</span> \
                           </button>\
                           <strong>' + strong + '</strong> ' + message + '\
                           </div>';

    $('#alertTarget').after(alert_bar);
    var session_id = $('#sessionID').html();
    ajaxHandler('pollplugins', {'session_id':session_id}, false );

}


/*
Notification Handler
add or remove notifications

Params:
    command: str = name of command
    postFields: str(json) = json string of POST options
    spinner: Bool = Overlay a loading spinner or not.'
 */

function notifications(notifyType, add, plugin_id, msg){
    if (add){
        if (notifyType == 'success'){
            // Increment the success counter
            var counter = parseInt($('#successcount').html());
            $('#successcount').html( counter+1);
            // Add the new li element

            var new_li = '<li><a href="#" onclick="ajaxHandler(\'pluginresults\', {\'plugin_id\':\'' + plugin_id + '\'}, false ); return false">'+ msg +'</a></li>';

            $('#notifysuccess').append(new_li)
        }
        if (notifyType == 'warning'){
            // Increment the success counter
            var counter = parseInt($('#warncount').html());
            $('#warncount').html( counter+1);
            // Add the new li element

            $('#notifywarn').append('<li><a href="#">'+ msg +'</a></li>');
        }
        if (notifyType == 'error'){
            // Increment the success counter
            var counter = parseInt($('#errorcount').html());
            $('#errorcount').html( counter+1);
            // Add the new li element
            $('#notifyerror').append('<li><a href="#">'+ msg +'</a></li>');
        }
    }else {
        if (notifyType == 'success'){
            // Reset
             $('#successcount').html(0);
            $('#notifysuccess').html('<li><a href="#" onclick="notifications(\'success\', false, \'\', \'Clear All\'); return false">Clear All</a></li>');
        }
        if (notifyType == 'warning'){
            // Reset
             $('#warncount').html(0);
            $('#notifywarn').html('<li><a href="#" onclick="notifications(\'warning\', false, \'\', \'Clear All\'); return false">Clear All</a></li>');
        }
            // Reset
             $('#errorcount').html(0);
            $('#notifyerror').html('<li><a href="#" onclick="notifications(\'error\', false, \'\', \'Clear All\'); return false">Clear All</a></li>');
        }
    var session_id = $('#sessionID').html();
    ajaxHandler('pollplugins', {'session_id':session_id}, false );
    }




/*
New Ajax Handler
Single Function to handle Ajax calls

Params:
    command: str = name of command
    postFields: str(json) = json string of POST options
    spinner: Bool = Overlay a loading spinner or not.'
 */


function ajaxHandler(command, postFields, spinner) {
    var dataType = '';
    // Convert postFields to json
    if (typeof postFields != 'string'){
        postOptions = postFields
    } else {
        var postOptions = JSON.parse(postFields);
    }

    // Sometimes we need to get values from form fields before the post.
    if (command == 'plugin_dir'){
        var postOptions = {'plugin_dir':$('#pluginDir').val()};
    }


    if (command == 'filtersessions'){
        postOptions['pluginname'] = $('#pluginname').val();
        postOptions['searchterm'] = $('#searchterm').val();

    }


    if (command == 'yara-string'){
        console.log('Yara Scanner');
        postOptions['yara-string'] = $('#yara-string').val();
        postOptions['yara-hex'] = $('#yara-hex').val();
        postOptions['yara-reverse'] = $('#yara-reverse').val();
        postOptions['yara-case'] = $('#yara-case').prop('checked');
        postOptions['yara-kernel'] = $('#yara-kernel').prop('checked');
        postOptions['yara-wide'] = $('#yara-wide').prop('checked');
        postOptions['yara-file'] = $('#yara-file').val();
        postOptions['yara-pid'] = $('#yara-pid').val();
    }

    if (command == 'memhex'){
        postOptions['start_offset'] = $('#start_offset').val();
        postOptions['end_offset'] = $('#end_offset').val();
    }
    if (command == 'memhexdump'){
        postOptions['start_offset'] = $('#start_offset').val();
        postOptions['end_offset'] = $('#end_offset').val();
        dataType = 'binary';
    }

    if (command == 'searchbar'){
        postOptions['search_type'] = $('#search_type').val();
        postOptions['search_text'] = $('#search_text').val();

    }

    if (command == 'addcomment'){
        postOptions['comment_text'] = document.getElementById('commentText').value;
        document.getElementById('commentText').value="";
    }

    // if selected show the loading image
    if (spinner == true){
        spinnerControl('open', 'Loading Data');
    }

    // Set Plugin Running
    if (command == 'runplugin'){
        var span_id = document.getElementById(postFields['plugin_name']+'_glyph');
        span_id.removeAttribute('class');
        span_id.className += 'glyphicon glyphicon-repeat';
        span_id.className += ' gly-spin';
    }


    // Try to add a session ID if one is present.
    var session_id = $('#sessionID').html();
    if(typeof session_id !== "undefined")
    {
      postOptions['session_id'] =session_id;
    }

    //Try to add active plugin ID
    if (postOptions['plugin_id'] == undefined)
    {
        if(typeof vActivePluginID !== "undefined")
        {
          postOptions['plugin_id'] = vActivePluginID;
        }
    }

  // $.post("/ajaxhandler/" + command + "/", postOptions, {responseType: 'binary'})
  $.ajax({
                url: "/ajaxhandler/" + command + "/",
                async: true,
                type: 'POST',
                data: postOptions,
                dataType: dataType,
  })
        // Success
        .done(function(data) {
            // POLL PLUGINS
            if (command == "pollplugins"){
                $('#pluginTable').html(data);

            // Filter Sessions
            } else if (command == "filtersessions"){
            for (var i = 0; i < data.length; i++) {
                session_id = data[i];
                console.log(session_id);
                $('tr').each(function(){
                    var tr = $(this);
                    if (tr.find('td:eq(0)').text()==session_id
                    ) tr.addClass('success');
                });
        }

            // Run Plugin
            }else if (command == "dropplugin"){
                notifications('warning', true, postOptions['plugin_id'], 'Plugin Deleted');

            // Run Plugin
            } else if (command == 'runplugin') {
                if (data.substring(0,5) == 'Error'){
                     notifications('error', true, postOptions['plugin_id'], 'View '+ data+ ' Output');
                } else if (data.substring(0,5) == 'Hmmmm') {
                    notifications('error', true, postOptions['plugin_id'], 'View '+ data+ ' Output');
                }else {

                notifications('success', true, postOptions['plugin_id'], 'View '+ data+ ' Output');
                }


            // Add Plugin Dir
            }else if (command == 'plugin_dir') {
                //alertBar('success', 'Added!', 'You have successfully added the plugin dir ' + data)
                location.reload();

            }else if (command == 'filedetails') {

                $('#fileModalDiv').html(data);
                //jQuery.noConflict();
                //Hide Any Open Modal
                $('.modal').modal('hide');
                // Open New Modal
                $('#fileModal').modal('show');

            }else if (command == 'hivedetails') {
                $('#hiveModalDiv').html(data);
                spinnerControl('close', 'Loading Data');
                $('#hiveModal').modal('show');
                // Enable table sorting
                $('#hiveTable').DataTable();

            // If target_div exists in the postoptions we are just writing out.
            }else if (postOptions["extension"]) {
                console.log("in Here");


                if (typeof data != 'string'){
                  data = data;
                } else {
                    var data = JSON.parse(data);
                }
                // Get the HTML we want to use
                var html_data = data['data'];
                // add additional JS
                var new_js = data['javascript'];
                eval(new_js);
                console.log(postOptions["target_div"]);
                $('#'+postOptions["target_div"]).html(html_data);

            }else if (command == 'dottree' || command == "vaddot") {
                console.log('DotTree');

                // Prepare the div
                $('#resultsTarget').html('<svg width="100%" height="100"><g/></svg>');
                var svg = d3.select("svg");
                var inner = d3.select("svg g");
                var zoom = d3.behavior.zoom().on("zoom", function() {
                      inner.attr("transform", "translate(" + d3.event.translate + ")" +
                                                  "scale(" + d3.event.scale + ")");
                    });
                svg.call(zoom);


                var render = dagreD3.render();
                var g = graphlibDot.read(data);
                // Set margins, if not present
                if (!g.graph().hasOwnProperty("marginx") &&
                    !g.graph().hasOwnProperty("marginy")) {
                  g.graph().marginx = 20;
                  g.graph().marginy = 20;
                }

                g.graph().transition = function(selection) {
                      return selection.transition().duration(500);
                    };

                d3.select("svg g").call(render, g);

                svg.attr("height", g.graph().height);

                var xCenterOffset = (g.graph().width) / 2;
                var yCenterOffset = (g.graph().height) / 2;

                inner.attr("transform", "translate("+xCenterOffset+", "+ yCenterOffset +")");



                $("svg").click(function( event ) {

                    if (command == 'dottree') {
                        // Reset the CSS
                        $("svg").find('rect').css("fill", "white");
                        $("svg").find('path').css("stroke", "white");

                        // Get nodes and paths
                        var node_list = inner.selectAll("g.node")[0];
                        var path_list = inner.selectAll("g.edgePath")[0];

                        // Get Selected Node
                        var selectedNode = $(event.target).closest('.node').find('rect');
                        if (selectedNode.length == 0) {
                            return false;
                        }
                        var selectedNodeID = selectedNode[0].__data__;

                        // Set selected node to blue
                        selectedNode.html("TEST");
                        selectedNode.css("fill", "blue");
                        // Find parents and children

                        for (i = 0; i < path_list.length; i++) {

                            var ppid = path_list[i].__data__.v;
                            var pid = path_list[i].__data__.w;
                            // Parent
                            if (pid == selectedNodeID) {
                                var ppid_int = parseInt(ppid.slice(4));
                                $(node_list[ppid_int - 1]).find('rect').css("fill", "red");
                                $(path_list[i]).find('path').css("stroke", "red");
                            }
                            // Children
                            if (ppid == selectedNodeID) {
                                var pid_int = parseInt(pid.slice(4));
                                $(node_list[pid_int - 1]).find('rect').css("fill", "yellow");
                                $(path_list[i]).find('path').css("stroke", "yellow");
                            }
                        }
                    }
            });

                //image = Viz(data, {format: "png-image-element"});
                //$(image).attr('id', 'proctree');
                //$(image).width('100%').height(500);
                //$('#resultsTarget').html(image);
                //$('#'+postOptions["target_div"]).append(image);

            }else if (command == "deleteobject") {
                if (postOptions['droptype'] == 'dumpfiles') {
                    $('.modal').modal('hide');
                    datatablesAjax(vActivePluginID);
                } else {
                    location.reload();
                }
            }else if (command == 'memhex') {
                $('#'+postOptions["target_div"]).html(data);

            }else if (command == 'memhexdump') {
               var empty = true;
               var pom = document.createElement('a');
               var url = URL.createObjectURL(data);
               pom.href=url;
               pom.setAttribute('download', 'dump.bin');
               pom.click();
               pom.remove();
            }else if (command == 'addcomment') {
                $('#comment-block').html(data);

            }else if (command == 'pluginresults') {
                // Close the spinner
                spinnerControl('close', 'Loading Data');
                // Load the data
                // Get the HTML we want to use
                var html_data = data['data'];
                // add additional JS
                var new_js = data['javascript'];
                $('#resultsTarget').html(html_data);
                // Enable table sorting

                // Return JQuery
                $('#resultsTable').DataTable({pageLength:25,scrollX: true,drawCallback: resultscontextmenu ($, window)});
                resultscontextmenu ($, window);

            }else if (command == 'searchbar') {
                // Close the spinner
                spinnerControl('close', 'Loading Data');
                // Load the data
                $('#resultsTarget').html(data);
                // Enable table sorting

                // Return JQuery
                $('#resultsTable').DataTable({pageLength:25,scrollX: true,drawCallback: resultscontextmenu ($, window)});
                resultscontextmenu ($, window);

            }else if (command == 'bookmark') {
                //

            }else if (command == 'procmem') {
                notifications('success', true, postOptions['plugin_id'], 'Check memdump plugin for your file.');

            }else if (command == 'filedump') {
                notifications('success', true, postOptions['plugin_id'], 'Check dumpfiles plugin for your file.');
            }else if (command == 'linux_find_file') {
                notifications('success', true, postOptions['plugin_id'], 'Check linux_find_file plugin for your file.');
            }else {
                if (postOptions['target_div']){
                    $('#'+postOptions["target_div"]).html(data);
                }else{
                    alertBar('danger', 'Spaghetti-Os!', 'Unable to find a valid command')
                }

            }

            // End of Done
        })
        // Failed
        .error(function(xhr, status) {
                if (xhr.status == 500) {
                    alertBar('danger', 'Spaghetti-Os!', 'Server Generated an Error 500 Please check the console. ' +
                        'Typically volitility couldnt handle a plugin correctly');
                }
            }

        )
        // CleanUp
        .always(function(xhr, status) {
               spinnerControl('close');
            }

        );
}

/*
resultscontextmenu
This is called whenever the datatables lib redraws a table.
On page switch search etc.

 */
function resultscontextmenu ($, window) {

    // Construct the Base Menu
    $("#contextMenu").empty();
    $("#contextMenu").append('<li><a tabindex="-1" href="#">BookMark Row</a></li>');
    $("#contextMenu").append('<li><a tabindex="-1" href="#">Search cell value</a></li>');
    $("#contextMenu").append('<li class="divider"></li>');
    $("#contextMenu").append('<li><a tabindex="-1" href="#">Export Row</a></li>');
    $("#contextMenu").append('<li><a tabindex="-1" href="#">Export Table</a></li>');

    // Add Rows based on current plugin
    var plugin_name = $('#pluginName').html();

    if (plugin_name == 'pslist') {
            $("#contextMenu").append('<li class="divider"></li>');
            $("#contextMenu").append('<li><a tabindex="-1" href="#">Store Process Mem</a></li>');
            $("#contextMenu").append('<li class="divider"></li>');
            $("#contextMenu").append('<li><a tabindex="-1" href="#">View VAD Tree</a></li>');
    }

    if (plugin_name == 'filescan') {
            $("#contextMenu").append('<li class="divider"></li>');
            $("#contextMenu").append('<li><a tabindex="-1" href="#">Store File Object</a></li>');

    }

    if (plugin_name == 'linux_enumerate_files') {
            $("#contextMenu").append('<li class="divider"></li>');
            $("#contextMenu").append('<li><a tabindex="-1" href="#">Store Linux File Object</a></li>');

    }

    // Construct the Menu

    var menus = {};
    $.fn.contextMenu = function (settings) {
        var $menu = $(settings.menuSelector);
        $menu.data("menuSelector", settings.menuSelector);
        if ($menu.length === 0) return;

        menus[settings.menuSelector] = {$menu: $menu, settings: settings};

        //make sure menu closes on any click
        $(document).click(function (e) {
            hideAll();
        });
        $(document).on("contextmenu", function (e) {
            var $ul = $(e.target).closest("ul");
            if ($ul.length === 0 || !$ul.data("menuSelector")) {
                hideAll();
            }
        });

        // Open context menu
        (function(element, menuSelector){
            element.on("contextmenu", function (e) {
                // return native menu if pressing control
                if (e.ctrlKey) return;

                hideAll();
                var menu = getMenu(menuSelector);

                //open menu
                menu.$menu
                .data("invokedOn", $(e.target))
                .show()
                .css({
                    position: "absolute",
                    left: getMenuPosition(e.clientX, 'width', 'scrollLeft'),
                    top: getMenuPosition(e.clientY, 'height', 'scrollTop')
                })
                .off('click')
                .on('click', 'a', function (e) {
                    menu.$menu.hide();

                    var $invokedOn = menu.$menu.data("invokedOn");
                    var $selectedMenu = $(e.target);

                    callOnMenuHide(menu);
                    menu.settings.menuSelected.call(this, $invokedOn, $selectedMenu);
                });

                callOnMenuShow(menu);
                return false;
            });
        })($(this), settings.menuSelector);

        function getMenu(menuSelector) {
            var menu = null;
            $.each( menus, function( i_menuSelector, i_menu ){
                if (i_menuSelector == menuSelector) {
                    menu = i_menu;
                    return false;
                }
            });
            return menu;
        }
        function hideAll() {
            $.each( menus, function( menuSelector, menu ){
                menu.$menu.hide();
                callOnMenuHide(menu);
            });
        }

        function callOnMenuShow(menu) {
            var $invokedOn = menu.$menu.data("invokedOn");
            if ($invokedOn && menu.settings.onMenuShow) {
                menu.settings.onMenuShow.call(this, $invokedOn);
            }
        }
        function callOnMenuHide(menu) {
            var $invokedOn = menu.$menu.data("invokedOn");
            menu.$menu.data("invokedOn", null);
            if ($invokedOn && menu.settings.onMenuHide) {
                menu.settings.onMenuHide.call(this, $invokedOn);
            }
        }

        function getMenuPosition(mouse, direction, scrollDir) {
            var win = $(window)[direction](),
                scroll = $(window)[scrollDir](),
                menu = $(settings.menuSelector)[direction](),
                position = mouse + scroll;

            // opening menu would pass the side of the page
            if (mouse + menu > win && menu < mouse) {
                position -= menu;
            }

            return position;
        }

    };


/*
Context Menu Handler
Identifies what option from the context menu was selected
and act accordingly.


 */
$("#resultsTable tbody tr").contextMenu({
    menuSelector: "#contextMenu",
    menuSelected: function ($invokedOn, $selectedMenu) {
        // When a dropdown is selected

        var row = $invokedOn.closest("tr");
        var menu_option = $selectedMenu.text();
        var cell_value = $invokedOn.text();
        //var plugin_id = $('#activepluginid').html();
        plugin_id = vActivePluginID;
        var row_num = row.find('td:first-child').text();
        //var row_id = $invokedOn.closest("tr").find('td:first-child').data('rowid');
        var row_id = plugin_id + '_' + row_num;

        if (menu_option == 'Search cell value') {
            // Set the value so the ajax handler reads it properly
            $('#search_type').val('plugin');
            // Set the search text
            $('#search_text').val(cell_value);
            // Get session
            var session_id = $('#sessionID').html();
            // Triger the ajax
            ajaxHandler('searchbar', {'session_id':session_id}, true);
            // reset search bar
            $('#search_text').val('');

        }

        if (menu_option == 'BookMark Row') {
            // Trigger the server side
            ajaxHandler('bookmark', {'row_id':row_id }, false);
            // Client Side update rows.
            if ($.inArray(parseInt(row_num), vBookMarks) > -1) {
                // Remove from array
                vBookMarks = jQuery.grep(vBookMarks, function(value) {
                  return value != row_num;
                });
            } else {
                vBookMarks.splice(0, 0, parseInt(row_num));
            }
            // Redraw Table
            $('#resultsTable').DataTable().draw(false);


        }

        if (menu_option == 'Store Process Mem') {
            var session_id = $('#sessionID').html();
            ajaxHandler('procmem', {'row_id':row_id, 'session_id':session_id}, true);
        }

        if (menu_option == 'Store File Object') {
            var session_id = $('#sessionID').html();
            ajaxHandler('filedump', {'row_id':row_id, 'session_id':session_id}, true);
        }

        if (menu_option == 'Store Linux File Object') {
            var session_id = $('#sessionID').html();
            ajaxHandler('linux_find_file', {'row_id':row_id, 'session_id':session_id, 'linux': true}, true);
        }

        if (menu_option == 'View VAD Tree') {
            // Get PID from Row
            // Lets find it properly get the column number using search then use this as index for the row.
            // This is because we can manipulate rows now.
            var pid_index = $('th:contains("PID")').index();

            var row_elem = $invokedOn.closest("tr");
            console.log(row_elem);
            //var pid = row_elem.cells[pid_index];
            //var pid = $invokedOn.closest("tr td:eq("+row_elem+")").text();
            var pid = row_elem.find('td:eq('+pid_index+')').text();


            console.log(pid);


            // Get session
            var session_id = $('#sessionID').html();

            // reset search bar
            ajaxHandler('vaddot', {'session_id':session_id,'target_div':'dotimage', 'pid': pid}, true );

        }

    },
    onMenuShow: function($invokedOn) {
        var tr = $invokedOn.closest("tr");
        $(tr).addClass("info");
    },
    onMenuHide: function($invokedOn) {
        var tr = $invokedOn.closest("tr");
        $(tr).removeClass("info");
    }
});



}


/*
Extra Files Uploader
Uses Ajax to handle the upload and some bootstrap to 'theme' the file input button

Credits to:
http://www.abeautifulsite.net/whipping-file-inputs-into-shape-with-bootstrap-3/
http://blog.teamtreehouse.com/uploading-files-ajax

 */
$(document).ready( function() {


    $('#file-form').submit( function(event) {

        var fileSelect = document.getElementById('file-select');
        event.preventDefault();
        // Update button text.
        $('#upload-button').html('Uploading ...');
        var files = fileSelect.files;
        var formData = new FormData();
            for (var i = 0; i < files.length; i++) {
            var file = files[i];
              // Add the file to the request.
              formData.append('files[]', file, file.name);
        }
        // Add Session ID
        formData.append('session_id', $('#sessionID').html());

        var xhr = new XMLHttpRequest();

        xhr.open('POST', '/addfiles/', true);

        xhr.onload = function () {
        if (xhr.status === 200) {
        // Success Update Elements
        $('#upload-button').html('Upload');
        $('#fileupload-block').html(xhr.responseText);

        } else {
            //Error
            alertBar('danger', 'Spaghetti-Os!', 'Server Generated an Error 500 Please check the console. ' +
                                    'Typically volitility couldnt handle a plugin correctly');
        }
        };

        // Send the Data.
xhr.send(formData);

    });
});


$(document).on('change', '.btn-file :file', function() {
  var input = $(this),
      numFiles = input.get(0).files ? input.get(0).files.length : 1,
      label = input.val().replace(/\\/g, '/').replace(/.*\//, '');
  input.trigger('fileselect', [numFiles, label]);
});

$(document).ready( function() {
    $('.btn-file :file').on('fileselect', function(event, numFiles, label) {

        var input = $(this).parents('.input-group').find(':text'),
            log = numFiles > 1 ? numFiles + ' files selected' : label;

        if( input.length ) {
            input.val(log);
        } else {
            if( log ) alert(log);
        }

    });
});

/*
Server side pagination of plugin rows.

 */

function datatablesAjax(plugin_id) {

    // Fill the First Page
    $.post("/ajaxhandler/pluginresults/", {'plugin_id':plugin_id})

        // Success
        .done(function(data) {
                // Get the HTML we want to use
                var html_data = data['data'];
                // add additional JS
                var new_js = data['javascript'];

            // Fill first 25 rows
            $('#resultsTarget').html(html_data);

            // then handover to ajax
            $('#resultsTable').DataTable({
                sDom: '<"top"flpr>rt<"bottom"ip><"clear">',
                oLanguage:{
                  sProcessing: '<h3 style="position:fixed;top:50%;left:50%;z-index:999999;background:#1a242f;";>Loading. Please Wait.</h3>'
                },
                processing: true,
                serverSide: true,
                ajax :{
                    url: '/ajaxhandler/pluginresults/',
                    type: 'POST',
                    data: function (d) {
                        d.plugin_id = plugin_id;
                        d.pagination = true;
                    },
                    dataSrc: function(json){
                       json.draw = json.data.draw;
                       json.recordsTotal = json.data.recordsTotal;
                       json.recordsFiltered = json.data.recordsFiltered;

                       return json.data.data;
                    }
                },
                createdRow: function (row, html_data, index) {
                    if ($.inArray(parseInt(html_data[0]), vBookMarks) > -1) {
                        $(row).addClass('success');
                    }
                },
                pageLength:25,
                scrollX: true,
                drawCallback: function( settings ) {resultscontextmenu ($, window);},
                deferLoading: vresultCount
            });
            resultscontextmenu ($, window);

            // Now run any additional JavaScript thats been added
            eval(new_js);

            // End of Done
        })
        // Failed
        .error(function(xhr, status) {
                if (xhr.status == 500) {
                    alertBar('danger', 'Spaghetti-Os!', 'Server Generated an Error 500 Please check the console. ' +
                        'Typically volitility couldnt handle a plugin correctly');
                }
            }

        )
        // CleanUp
        .always(function(xhr, status) {
               spinnerControl('close');
            }

        );
}

$(document).ready(function () {
	$('label.tree-toggler').click(function () {
		$(this).parent().children('ul.tree').toggle(300);
	});
});
