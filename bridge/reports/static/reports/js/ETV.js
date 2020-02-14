/*
 * Copyright (c) 2018 ISP RAS (http://www.ispras.ru)
 * Ivannikov Institute for System Programming of the Russian Academy of Sciences
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * ee the License for the specific language governing permissions and
 * limitations under the License.
 */

function toggle_by_id(identifier) {
    element = document.getElementById(identifier);
    if (!element) {
        return;
    }
    if (element.hidden) {
        element.hidden = false;
    } else {
        element.hidden = true;
    }
}

$(document).ready(function () {
    var ready_for_next_string = false, etv_window = $('#ETV_error_trace'), etv_attrs = $('#etv-attributes');

    if (!etv_window.length) {
        return false;
    }

    function get_source_code(line, filename) {

        var source_code_window = $('#ETV_source_code');

        function select_src_string() {
            var selected_src_line = $('#ETVSrcL_' + line);
            if (selected_src_line.length) {
                source_code_window.scrollTop(source_code_window.scrollTop() + selected_src_line.position().top - source_code_window.height() * 3/10);
                selected_src_line.parent().addClass('ETVSelectedLine');
            }
            else {
                //err_notify($('#error___line_not_found').text()); // this one is very annoying
            }
        }
        if (filename === $('#ETVSourceTitleFull').text()) {
            select_src_string();
        }
        else {
            ready_for_next_string = false;
            $.ajax({
                url: '/reports/get_source/' + $('#report_pk').val() + '/',
                type: 'POST',
                data: {file_name: filename, witness_type: $('#witness_type').text()},
                success: function (data) {
                    if (data.error) {
                        $('#ETVSourceTitle').empty();
                        source_code_window.empty();
                        err_notify(data.error);
                    }
                    else if (data.name && data.content) {
                        var title_place = $('#ETVSourceTitle');
                        title_place.text(data.name);
                        $('#ETVSourceTitleFull').text(data.name);
                        title_place.popup();
                        src_filename_trunc();
                        source_code_window.html(data.content);
                        select_src_string();
                        ready_for_next_string = true;
                    }
                }
            });
        }
    }
    last_viewed_src = null;
    function get_source_code_standalone(line, filename) {
        var file_name = '#src_files' + filename.replace(/[^a-zA-Z0-9_]/g, '');
        file = $(file_name);
        function select_src_string() {
            var selected_src_line = $(file_name + ' #ETVSrcL_' + line);
            if (selected_src_line.length) {
                file.scrollTop(file.scrollTop() + selected_src_line.position().top - file.height() * 3/10);
                selected_src_line.parent().addClass('ETVSelectedLine');
            }
        }
        if (filename === $('#ETVSourceTitleFull').text()) {
            select_src_string();
        }
        else {
            var title_place = $('#ETVSourceTitle');
            title_place.text(filename);
            $('#ETVSourceTitleFull').text(filename);
            title_place.popup();
            src_filename_trunc();
            if (last_viewed_src) {
                last_viewed_src.hide();
            }
            last_viewed_src = file;
            $(file).show();
            select_src_string();
        }
    }

    $('#ETVSourceTitle').click(function () {
        src_filename_trunc();
    });

    $('.filecontent').each(function () {
        $(this).html($(this).text());
    });

    function open_function(hidelink, shift_pressed, change_state) {
        if (change_state) {
            var func_line = hidelink.parent().parent(), collapse_icon = hidelink.find('i').first();
            collapse_icon.removeClass('right');
            collapse_icon.addClass('down');
            func_line.removeClass('func_collapsed');
            func_line.find('.ETV_FuncName').hide();
            func_line.find('.ETV_FuncCode').show();
        }
        $('.' + hidelink.attr('id')).each(function () {
            var inner_hidelink = $(this).find('.ETV_HideLink');
            if (!($(this).hasClass('commented') && ($(this).hasClass('func_collapsed') || inner_hidelink.length == 0))) {
                $(this).show();
            }
            if (inner_hidelink.length == 1) {
                if ($(this).hasClass('func_collapsed')) {
                    if (shift_pressed) {
                        $(this).show();
                        open_function(inner_hidelink, shift_pressed, shift_pressed);
                    }
                    else if (!$(this).hasClass('commented')) {
                        $(this).show();
                    }
                }
                else {
                    $(this).show();
                    open_function(inner_hidelink, shift_pressed, false);
                }
            }
            else if (!$(this).hasClass('commented')) {
                $(this).show();
            }
        });
    }

    function close_function(hidelink, shift_pressed, change_state) {
        if (change_state) {
            var func_line = hidelink.parent().parent(), collapse_icon = hidelink.find('i').first();
            collapse_icon.removeClass('down');
            collapse_icon.addClass('right');
            func_line.addClass('func_collapsed');
            func_line.find('.ETV_FuncCode').hide();
            func_line.find('.ETV_FuncName').show();
        }
        $('.' + hidelink.attr('id')).each(function () {
            $(this).hide();
            var inner_hidelink = $(this).find('.ETV_HideLink');
            if (inner_hidelink.length == 1) {
                close_function(inner_hidelink, shift_pressed, shift_pressed);
            }
        });
    }

    $('.ETV_GlobalExpanderLink').click(function (event) {
        event.preventDefault();
        var global_icon = $(this).find('i').first();
        if (global_icon.hasClass('unhide')) {
            global_icon.removeClass('unhide').addClass('hide');
            etv_window.find('.global:not(.commented)').show();
        }
        else {
            global_icon.removeClass('hide').addClass('unhide');
            etv_window.find('.global:not([data-type="comment"])').hide();
        }
    });

    $('.ETV_HideLink').click(function (event) {
        event.preventDefault();
        if ($(this).find('i').first().hasClass('right')) {
            open_function($(this), event.shiftKey, true);
        }
        else {
            close_function($(this), event.shiftKey, true);
        }
    });
    $('.ETV_DownHideLink').click(function () {
        $('#' + $(this).parent().parent().attr('class')).click();
    });

    $('.ETV_La').click(function (event) {
        event.preventDefault();
        var source_code = $(this).parent().parent().find('span[class="ETV_FuncCode"]').text();
        if (!source_code) {
            source_code = $(this).parent().parent().find('span[class="ETV_CODE"]').text();
        }
        var desc_addition = "<b>line " + parseInt($(this).text()) + "</b>: <i><code>'" + source_code + "'</code></i>";
        $('#mark_description').val($('#mark_description').val() + desc_addition);
        $('.ETVSelectedLine').removeClass('ETVSelectedLine');
        $('.ETV_LN_Note_Selected').removeClass('ETV_LN_Note_Selected');
        $('.ETV_LN_Warning_Selected').removeClass('ETV_LN_Warning_Selected');
        if ($(this).next('span.ETV_File').length) {
            var src_line = parseInt($(this).text());
            var src_file = $(this).next('span.ETV_File').text();
            if ($('#standalone').text()) {
                get_source_code_standalone(src_line, src_file);
            } else {
                get_source_code(src_line, src_file);
            }
        }
        var whole_line = $(this).parent().parent();
        whole_line.addClass('ETVSelectedLine');

        var assume_window = $('#ETV_assumes');
        if (assume_window.length) {
            assume_window.empty();
            whole_line.find('span[class="ETV_CurrentAssumptions"]').each(function () {
                var assume_ids = $(this).text().split(';');
                $.each(assume_ids, function (i, v) {
                    var curr_assume = $('#' + v);
                    if (curr_assume.length) {
                        assume_window.append($('<span>', {
                            text: curr_assume.text(),
                            style: 'color: red'
                        })).append($('<br>'));
                    }
                });
            });
            whole_line.find('span[class="ETV_Assumptions"]').each(function () {
                var assume_ids = $(this).text().split(';');
                $.each(assume_ids, function (i, v) {
                    var curr_assume = $('#' + v);
                    if (curr_assume.length) {
                        assume_window.append($('<span>', {
                            text: curr_assume.text()
                        })).append($('<br>'));
                    }
                });
            });
        }
    });
    var warn;
    var note;
    var note_changes = {}, warn_changes = {};

    var last_lc;
    $('.ETV_LN').contextmenu(function(event) {
        if (!$('#edit_et').val()) {
            return true;
        }
        last_lc = $(this).parent().filter('span[class="ETV_LC"]');
        $('#change_et_form').show();
        warn = $(this).parent().find('a[class="ETV_ShowCommentCode ETV_WarnText"]');
        $('#form_modify_warn').val(warn.text());
        note = $(this).parent().find('a[class="ETV_ShowCommentCode ETV_NoteText"]');
        $('#form_modify_note').val(note.text());
        var id = $(this).find('span[class="ETV_ID"]').text();
        $('#form_id').val(id);
        return false;
    });
    $('#change_et_ok').click(function(event) {
        var id = $('#form_id').val();

        var warn_val = $('#form_modify_warn').val();
        var note_val = $('#form_modify_note').val();

        warn.text(warn_val);
        note.text(note_val);
        note_changes[id] = note_val;
        warn_changes[id] = warn_val;
        if (note_val) {
            note.parent().find('.ETV_CODE').hide();
            note.parent().find('.ETV_FuncCode').hide();
            note.parent().find('.ETV_FuncName').hide();
        }
        if (warn_val) {
            warn.parent().find('.ETV_CODE').hide();
            warn.parent().find('.ETV_FuncCode').hide();
            warn.parent().find('.ETV_FuncName').hide();
        }
        if (!note_val && !warn_val) {
            warn.parent().find('.ETV_CODE').hide();
            warn.parent().find('.ETV_FuncName').hide();
            note.parent().find('.ETV_CODE').show();
            note.parent().find('.ETV_FuncName').show();
        }

        $('#change_et_form').hide();
        return false;
    });
    $('#change_et_cancel').click(function(event) {
        $('#change_et_form').hide();
        return false;
    });
    $('i[id^="etv_warn_"]').click(function(event) {
        warn_changes[$(this).parent().find('.ETV_ID').text()] = "";
        $(this).parent().remove();
        return false;
    });
    $('i[id^="etv_note_"]').click(function(event) {
        note_changes[$(this).parent().find('.ETV_ID').text()] = "";
        $(this).parent().remove();
        return false;
    });
    $('#apply_changes').click(function(event) {
        $(this).addClass('disabled');
        var is_modifiable = $('#is_modifiable').is(':checked');
        if (!is_modifiable) {
            is_modifiable = '';
        }
        $.post(
            '/reports/unsafe/' + $('#report_pk').val() +'/apply/',
            {
                "notes": JSON.stringify(note_changes),
                "warns": JSON.stringify(warn_changes),
                "is_modifiable": is_modifiable
            },
            function (data) {
                if (data.error) {
                    err_notify(data.error);
                    $('#apply_changes').removeClass('disabled');
                    return false;
                }
                window.location.href = window.location.href.replace('/edit/', '/');
            }
        );
    });
    if (document.getElementById("upload_edited_trace")) {
        $('#upload_edited_trace_popup').modal({transition: 'vertical flip'}).modal('attach events', '#upload_edited_trace', 'show');
        $('#upload_edited_trace_cancel').click(function () {
            $('#upload_edited_trace_popup').modal('hide');
        });
        $('#upload_edited_trace_input').on('fileselect', function () {
            $('#upload_edited_trace_filename').text($(this)[0].files[0].name);
        });
        $('#upload_edited_trace_start').click(function () {
            var files = $('#upload_edited_trace_input')[0].files, data = new FormData();
            if (files.length <= 0) {
                err_notify($('#error__no_file_chosen').text());
                return false;
            }
            data.append('file', files[0]);
            $('#upload_edited_trace_popup').modal('hide');
            $('#dimmer_of_page').addClass('active');
            $.ajax({
                url: '/reports/unsafe/' + $('#report_pk').val() + '/upload/',
                type: 'POST',
                data: data,
                dataType: 'json',
                contentType: false,
                processData: false,
                mimeType: 'multipart/form-data',
                xhr: function() {
                    return $.ajaxSettings.xhr();
                },
                success: function (data) {
                    $('#dimmer_of_page').removeClass('active');
                    if (data.error) {
                        err_notify(data.error);
                    }
                    else {
                        window.location.replace('');
                    }
                }
            });
        });
    }
    $('#cancel_changes').click(function(event) {
        $(this).addClass('disabled');
        $.post(
            '/reports/unsafe/' + $('#report_pk').val() +'/cancel/',
            {
                "notes": JSON.stringify(note_changes),
                "warns": JSON.stringify(warn_changes)
            },
            function (data) {
                if (data.error) {
                    err_notify(data.error);
                    $('#cancel_changes').removeClass('disabled');
                    return false;
                }
                window.location.href = window.location.href.replace('/edit/', '/');
            }
        );
    });
    $('.ETV_ShowCommentCode').click(function () {
        var next_code = $(this).parent().parent().next('span');
        if (next_code.length > 0) {
            if (next_code.is(':hidden')) {
                next_code.show();
                if (next_code.find('.ETV_HideLink').find('i').hasClass('right')) {
                    next_code.find('.ETV_HideLink').click();
                }
                var next_src_link = next_code.find('.ETV_La').first();
                if (next_src_link.length) {
                    next_src_link.click();
                }
            }
            else {
                if (next_code.find('.ETV_HideLink').find('i').hasClass('down')) {
                    next_code.find('.ETV_HideLink').click();
                }
                next_code.hide();
            }
        }
    });

    function select_next_line() {
        var selected_line = etv_window.find('.ETVSelectedLine').first();
        if (selected_line.length) {
            var next_line = selected_line.next(),
                next_line_link;
            while (next_line.length) {
                if (next_line.is(':visible')) {
                    if (next_line.find('a.ETV_La').length) {
                        next_line_link = next_line.find('a.ETV_La');
                        if (next_line_link.length) {
                            next_line_link.click();
                            return true;
                        }
                    }
                    else if (next_line.find('a.ETV_ShowCommentCode').length && !next_line.next('span').is(':visible')) {
                        next_line.next('span').find('.ETV_La').click();
                        next_line.addClass('ETVSelectedLine');
                        return true;
                    }
                }
                next_line = next_line.next()
            }
        }
        return false;
    }
    function select_prev_line() {
        var selected_line = etv_window.find('.ETVSelectedLine').first();
        if (selected_line.length) {
            var prev_line = selected_line.prev(),
                prev_line_link;
            while (prev_line.length) {
                if (prev_line.is(':visible')) {
                    if (prev_line.find('a.ETV_La').length) {
                        prev_line_link = prev_line.find('a.ETV_La');
                        if (prev_line_link.length) {
                            prev_line_link.click();
                            return true;
                        }
                    }
                    else if (prev_line.find('a.ETV_ShowCommentCode').length && !prev_line.next('span').is(':visible')) {
                        prev_line.next('span').find('.ETV_La').click();
                        prev_line.addClass('ETVSelectedLine');
                        return true;
                    }
                }
                prev_line = prev_line.prev()
            }
        }
        return false;
    }
    $('#etv_next_step').click(select_next_line);
    $('#etv_prev_step').click(select_prev_line);

    var interval;
    function play_etv_forward() {
        var selected_line = etv_window.find('.ETVSelectedLine').first();
        if (!selected_line.length) {
            err_notify($('#error___no_selected_line').text());
            clearInterval(interval);
            return false;
        }
        if ($.active > 0 || !ready_for_next_string) {
            return false;
        }
        etv_window.scrollTop(etv_window.scrollTop() + selected_line.position().top - etv_window.height() * 3/10);
        if (!select_next_line()) {
            clearInterval(interval);
            success_notify($('#play_finished').text());
            return false;
        }
        return false;
    }
    function play_etv_backward() {
        var selected_line = etv_window.find('.ETVSelectedLine').first();
        if (!selected_line.length) {
            err_notify($('#error___no_selected_line').text());
            clearInterval(interval);
            return false;
        }
        if ($.active > 0 || !ready_for_next_string) {
            return false;
        }
        etv_window.scrollTop(etv_window.scrollTop() + selected_line.position().top - etv_window.height() * 7/10);
        if (!select_prev_line()) {
            clearInterval(interval);
            success_notify($('#play_finished').text());
            return false;
        }
        return false;
    }

    $('#etv_play_forward').click(function () {
        clearInterval(interval);
        var speed = parseInt($('#select_speed').val());
        interval = setInterval(play_etv_forward, speed * 1000);
    });
    $('#etv_play_backward').click(function () {
        clearInterval(interval);
        var speed = parseInt($('#select_speed').val());
        interval = setInterval(play_etv_backward, speed * 1000);
    });
    $('#etv_pause_play').click(function () {
        clearInterval(interval);
    });

    $('.ETV_LN_Note, .ETV_LN_Warning').click(function () {
        var next_src_link = $(this).parent().next('span').find('.ETV_La').first();
        if (next_src_link.length) {
            next_src_link.click();
        }
        if ($(this).hasClass('ETV_LN_Note')) {
            $(this).addClass('ETV_LN_Note_Selected');
        }
        else {
            $(this).addClass('ETV_LN_Warning_Selected');
        }
    });

    etv_window.scroll(function () {
        $(this).find('.ETV_LN').css('left', $(this).scrollLeft());
    });
    $('.filecontent').scroll(function () {
        $(this).find('.ETVSrcL').css('left', $(this).scrollLeft());
    });
    $('#etv_start').click(function () {
        etv_window.children().each(function () {
            if ($(this).is(':visible')) {
                var line_link = $(this).find('a.ETV_La');
                etv_window.scrollTop(etv_window.scrollTop() + $(this).position().top - etv_window.height() * 3/10);
                if (line_link.length) {
                    line_link.click();
                    return false;
                }
            }
        });
        $('#etv_play_forward').click();
    });

    $('#etv_start_backward').click(function () {
        var next_child = etv_window.children().last();
        while (next_child) {
            if (next_child.is(':visible')) {
                var line_link = next_child.find('a.ETV_La');
                if (line_link.length) {
                    etv_window.scrollTop(etv_window.scrollTop() + next_child.position().top - etv_window.height() * 7/10);
                    line_link.click();
                    next_child = null;
                }
            }
            if (next_child) {
                next_child = next_child.prev();
            }
        }
        $('#etv_play_backward').click();
    });
    etv_window.children().each(function () {
        if ($(this).is(':visible')) {
            var line_link = $(this).find('a.ETV_La');
            etv_window.scrollTop(etv_window.scrollTop() + $(this).position().top - etv_window.height() * 3/10);
            if (line_link.length) {
                line_link.click();
                return false;
            }
        }
    });
    $('.ETV_Action').click(function () {
        $(this).parent().find('.ETV_HideLink').click();
        var src_link = $(this).parent().parent().find('.ETV_La').first();
        if (src_link.length) {
            src_link.click();
        }
    });
    $('.ETV_CallbackAction').click(function () {
        $(this).parent().find('.ETV_HideLink').click();
        var src_link = $(this).parent().parent().find('.ETV_La').first();
        if (src_link.length) {
            src_link.click();
        }
    });
    $('#toggle_eyes').click(function () {
        $(this).addClass('disabled');
        $('.ETV_ShowCode').click();
        $(this).removeClass('disabled');
    });
    $('#toggle_functions').click(function () {
        $(this).addClass('disabled');
        $('.ETV_HideLink').click();
        $('.ETV_ShowCode').click();
        $(this).removeClass('disabled');
    });
    $('#ldv_button').click(function () {
        if ($(this).hasClass('x')) {
            var et = document.getElementById('ETV_error_trace');
            var children = et.children;
            for (var i = 0; i < children.length; i++) {
                children[i].style.display = "inline";
            }
            $(this).removeClass('x');
        } else {
            $(this).addClass('x');
            var et = document.getElementById('ETV_error_trace');
            var children = et.children;
            for (var i = 0; i < children.length; i++) {
                if (!children[i].className.includes('0_0_0_0')) {
                    children[i].style.display = "none";
                }
                if (!children[i].className.includes('0_0_0_0') && !children[i].className.includes('func_collapsed')) {
                    var str = children[i].getElementsByClassName('ETV_LC');
                    for (var j = 0; j < str.length; j++) {
                        var cd = str[j].getElementsByClassName('ETV_CODE');
                        for (var k = 0; k < cd.length; k++) {
                            if (cd[k].children.length > 1) {
                                if (cd[k].innerHTML.includes('ldv_')) {
                                    children[i].style.display = "inline";
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    var toggle_notes_state = true;
    $('#toggle_notes').click(function () {
        $(this).addClass('disabled');
        $($('.ETV_ShowCommentCode').get().reverse()).each(function (){
            if ($(this).text()) {
                var next_code = $(this).parent().parent().next('span');
                if (next_code.length > 0) {
                    if (toggle_notes_state) {
                        next_code.show();
                        if (next_code.find('.ETV_HideLink').find('i').hasClass('right')) {
                            next_code.find('.ETV_HideLink').click();
                        }
                    } else {
                        if (next_code.find('.ETV_HideLink').find('i').hasClass('down')) {
                            next_code.find('.ETV_HideLink').click();
                        }
                        next_code.hide();
                    }
                }
            }
        });
        toggle_notes_state = !toggle_notes_state;
        $(this).removeClass('disabled');
    });
    var toggle_hidden_notes_state = true;
    $('#toggle_hidden_notes').click(function () {
        $(this).addClass('disabled');
        $($('.ETV_LN_Note').get().reverse()).each(function (){
            var is_hidden = $(this).parent().find('span[class="ETV_HIDDEN_NOTE"]');
            if (is_hidden.text()) {
                var hidden_note = $(this).parent();
                if (toggle_hidden_notes_state) {
                    hidden_note.show();
                } else {
                    hidden_note.hide();
                }
            }
        });
        toggle_hidden_notes_state = !toggle_hidden_notes_state;
        $(this).removeClass('disabled');
    });

    $('.ETV_ShowCode').click(function () {
        var whole_line = $(this).parent().parent(), scope = $(this).attr('id'), showcode_icon = $(this).find('i');
        if (showcode_icon.hasClass('unhide')) {
            showcode_icon.removeClass('unhide').addClass('hide');
            whole_line.find('.ETV_FuncCode').show();
            whole_line.find('.ETV_FuncName').hide();
            $('.' + scope).each(function () {
                var curr_line_type = $(this).attr('data-type');
                if ((curr_line_type == 'normal' || curr_line_type == 'eye-control') && (!$(this).hasClass('commented'))) {
                    $(this).show();
                }
            });
        }
        else {
            showcode_icon.removeClass('hide').addClass('unhide');
            whole_line.find('.ETV_FuncCode').hide();
            whole_line.find('.ETV_FuncName').show();
            $('.' + scope).each(function () {
                var curr_line_type = $(this).attr('data-type'),
                    curr_hidelink = $(this).find('a[class="ETV_HideLink"]');
                if (!($(this).hasClass('func_collapsed') && curr_hidelink.length)) {
                    curr_hidelink.click();
                }
                if (curr_line_type == 'normal' || curr_line_type == 'eye-control') {
                    $(this).hide();
                }
            });
        }
    });
    if ($('#witness_type').text() == 'correctness') {
        $('#toggle_eyes').click();
    }
});