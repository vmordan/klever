/*
 * Copyright (c) 2019 ISP RAS (http://www.ispras.ru)
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

var pages_stack = [];
var cur_page = 0;

function activate(help_page, fwd=true) {
    $('div[class="item help"]').each(function () {
        if ($(this).attr('id') == help_page) {
            $(this).css("background", "#dddddd");
        } else {
            $(this).css("background", "#ffffff");
        }
    });
    var help_desc = $('#help_details');
    $.ajax({
        url: '/get_help_pages/' + help_page + '/',
        type: 'POST',
        data: {},
        success: function (data) {
            help_desc.html(data);
            if (help_page == 'about') {
                $('#control_home').addClass('disabled');
            } else {
                $('#control_home').removeClass('disabled');
            }
            if (fwd) {
                if (cur_page < pages_stack.length) {
                    $('#control_forward').addClass('disabled');
                    pages_stack = pages_stack.slice(0, cur_page);
                }
                pages_stack.push(help_page);
                cur_page += 1;
                if (cur_page > 1) {
                    $('#control_back').removeClass('disabled');
                }
            }
        }
    });
}

$(document).ready(function () {
    var manager_input = $('#manager_username'), service_input = $('#service_username');
    pages_stack = [];
    function check_usernames() {
        if (service_input.length && manager_input.length) {
            if (manager_input.val().length == 0 || service_input.val().length == 0) {
                $('#populate_button').addClass('disabled');
                $('#usernames_required_err').show();
                return false;
            }
            else {
                $('#usernames_required_err').hide();
            }
            if (manager_input.val().length && manager_input.val() == service_input.val()) {
                $('#populate_button').addClass('disabled');
                $('#usernames_err').show();
            }
            else {
                $('#populate_button').removeClass('disabled');
                $('#usernames_err').hide();
            }
        }
    }
    manager_input.on('input', function () {
        check_usernames();
    });
    service_input.on('input', function () {
        check_usernames();
    });
    check_usernames();
    $('#populate_button').click(function () {
        $(this).addClass('disabled');
    });

    var start_help_page = $('#start_help_page').text();
    if (start_help_page.length) {
        activate(start_help_page);
    } else {
        activate('about');
    }

    $('.ui.sidebar').sidebar('toggle');
    $('#control_home').click(function () {
        activate('about');
    });
    $('#control_back').click(function () {
        cur_page -= 1;
        activate(pages_stack[cur_page - 1], false);
        if (cur_page <= 1) {
            $('#control_back').addClass('disabled');
        }
        $('#control_forward').removeClass('disabled');
    });
    $('#control_forward').click(function () {
        activate(pages_stack[cur_page], false);
        cur_page += 1;
        if (cur_page == pages_stack.length) {
            $('#control_forward').addClass('disabled');
        }
        if (cur_page > 1) {
            $('#control_back').removeClass('disabled');
        }
    });
});
