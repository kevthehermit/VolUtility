/**
 * Part of VolUtility
 */



function sessionCreate() {
    jQuery.noConflict();
    $('#sessionModal').modal('hide');
    spinnerControl('open', 'Cats are preparing your image for analysis');
}



// New Stuff Starts Here =========================================================================== //

/*
Download to file
Single Function to handle file downloads.

Params:
    command: str = name of command
    postFields: str(json) = json string of POST options
    spinner: Bool = Overlay a loading spinner or not.'
 */

function changeCSS(cssname){
    var newcss = '/static/css/bootstrap_' + cssname + '.min.css';
    $('#bootswatch').attr('href', newcss);
}


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
        document.getElementById('loadingtext').innerHTML = message
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

    if (command == 'yara'){
        postOptions['rule_file'] = $('#rule_file').val();
    }

    if (command == 'yara-string'){
        postOptions['yara-string'] = $('#yara-string').val();
        postOptions['yara-hex'] = $('#yara-hex').val();
        postOptions['yara-reverse'] = $('#yara-reverse').val();
        postOptions['yara-case'] = $('#yara-case').prop('checked');
        postOptions['yara-kernel'] = $('#yara-kernel').prop('checked');
        postOptions['yara-wide'] = $('#yara-wide').prop('checked');
        postOptions['yara-file'] = $('#yara-file').val();
    }

    if (command == 'memhex' || command == 'memhexdump'){
        postOptions['start_offset'] = $('#start_offset').val();
        postOptions['end_offset'] = $('#end_offset').val();
    }

    if (command == 'searchbar'){
        postOptions['search_type'] = $('#search_type').val();
        postOptions['search_text'] = $('#search_text').val();

    }

    if (command == 'addcomment'){
        postOptions['comment_text'] = document.getElementById('commentText').value;
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

    $.post("/ajaxhandler/" + command + "/", postOptions)

        // Success
        .done(function(data) {
            // POLL PLUGINS
            if (command == "pollplugins"){
                $('#pluginTable').html(data);

            // DROP PLUGINS
            } else if (command == "dropplugin"){
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
                jQuery.noConflict();
                $('#fileModal').modal('show');

            }else if (command == 'hivedetails') {
                $('#hiveModalDiv').html(data);
                jQuery.noConflict();
                spinnerControl('close', 'Loading Data');
                $('#hiveModal').modal('show');
                // Enable table sorting
                jQuery.noConflict();
                $('#hiveTable').DataTable();

            }else if (command == "virustotal" || command == "yara" || command == "strings" || command == "yara-string") {
                $('#'+postOptions["target_div"]).html(data);

            }else if (command == 'dottree') {
                image = Viz(data, {format: "png-image-element"});
                $(image).attr('id', 'proctree');
                $(image).width('100%').height(500);
                $('#resultsTarget').append(image);
                //$('#'+postOptions["target_div"]).append(image);

            }else if (command == "dropsession") {
                window.location.reload();

            }else if (command == 'memhex') {
                $('#'+postOptions["target_div"]).html(data);

            }else if (command == 'memhexdump') {
                var empty = true;

            }else if (command == 'addcomment') {
                $('#comment-block').html(data);

            }else if (command == 'pluginresults' || command == 'searchbar') {
                $('#resultsTarget').html(data);
                // Enable table sorting
                $('#resultsTable').DataTable({pageLength:25, scrollX: true, drawCallback: resultscontextmenu ($, window)});
                resultscontextmenu ($, window);

            }else if (command == 'bookmark') {
                var row_id = postOptions['row_id'];
                var row = $('#resultsTable').find("[data-rowid='" + row_id + "']").parent('tr');
                if (data == 'add') {

                    $(row).addClass("success");
                } else {
                    $(row).removeClass("success");
                }
            }else if (command == 'procmem') {
                //pass
            }else {
                alertBar('danger', 'Spaghetti-Os!', 'Unable to find a valid command')
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



function resultscontextmenu ($, window) {

    // Add any plugin specific rows
    var plugin_name = $('#pluginName').html();

    if (plugin_name == 'pslist') {

        if ( $('#contextMenu:contains("Store Process Mem")').length ) {
            //exists
        } else {
            $("#contextMenu").append('<li><a tabindex="-1" href="#">Store Process Mem</a></li>');
        }

    }


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



$("#resultsTable tbody tr").contextMenu({
    menuSelector: "#contextMenu",
    menuSelected: function ($invokedOn, $selectedMenu) {
        // When a dropdown is selected

        var row = $invokedOn.closest("tr");
        var menu_option = $selectedMenu.text();
        var cell_value = $invokedOn.text();
        var row_num = $invokedOn.closest("tr").find('td:first-child').text();
        var row_id = $invokedOn.closest("tr").find('td:first-child').data('rowid');


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
            ajaxHandler('bookmark', {'row_id':row_id }, false);
        }

        if (menu_option == 'Store Process Mem') {
            var session_id = $('#sessionID').html();
            ajaxHandler('procmem', {'row_id':row_id, 'session_id':session_id}, false);
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


