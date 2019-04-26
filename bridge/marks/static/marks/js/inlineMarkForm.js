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

function get_description() {
    var tmp_div = $('<div>').html($('#mark_description').val());
    tmp_div.find('script').remove();
    tmp_div.find('*').each(function () {
        var element_in_div = $(this);
        $.each($(this)[0].attributes, function (i, attr) { if (attr.name.match("^on")) element_in_div.removeAttr(attr.name) });
    });
    return tmp_div.html();
}

function collect_markdata() {
    var obj_type = $('#obj_type').val(), mark_data = {
        description: get_description(), is_modifiable: true,
        status: $("input[name='selected_status']:checked").val(),
        comment: $('#inline_mark_comment').val()
    };

    if (obj_type === 'unknown') {
        mark_data['problem'] = $('#unknown_problem_pattern').val();
        mark_data['function'] = $('#unknown_function').val();
        mark_data['is_regexp'] = $('#is_regexp').is(':checked');
        mark_data['link'] = $('#unknown_link').val();
    }
    else {
        mark_data['verdict'] = $("input[name='selected_verdict']:checked").val();
        mark_data['tags'] = get_tags_values();
    }
    if (obj_type == 'unsafe') {
        mark_data['edited_error_trace'] = $('#converted_error_trace').val();
        mark_data['conversion_function'] = $('#conversion_function').val();
        mark_data['comparison_function'] = $('#comparison_function').val();
        mark_data['similarity_threshold'] = $('#similarity_threshold').val();
        mark_data['conversion_function_args'] = "*DO NOT CHANGE*";
        mark_data['use_edited_error_trace'] = $('#use_edited_error_trace').is(':checked');
    }
    mark_data['report_to_redirect'] = $('#report_pk').val();
    return JSON.stringify(mark_data);
}

function save_inline_mark() {
    $('#progress_bar_popup').modal('show');
    var mark_id = 0;
    var update_progress_interval = null;
    var time_start = performance.now();
    if ($('#action').val() == 'edit') {
        mark_id = $('#obj_id').val();
    }
    update_progress_interval = setInterval(function() {mark_id = update_progress(mark_id, time_start);}, 1000);

    $(this).addClass('disabled');
    $.post(
        '/marks/' + $('#obj_type').val() + '/' + $('#obj_id').val() + '/' + $('#inline_action').val() + '/',
        {data: collect_markdata()},
        function (data) {
            if (data.error) {
                $('#save_mark_btn').removeClass('disabled');
                $('#progress_bar_popup').modal('hide');
                $('#progress_bar_popup').modal('hide');
                clearInterval(update_progress_interval);
                err_notify(data.error);
            }
            else if ('cache_id' in data) {
                var overall_time = (performance.now() - time_start) / 1000;
                window.location.href = '/marks/' + $('#obj_type').val() + '/association_changes/' + data['cache_id']
                    + '/?time=' + overall_time + "&report_to_redirect=" + data['report_to_redirect'];
            }
        }
    );
}

window.get_inline_mark_form = function(container, obj_id, action) {
    var report_type = $('#report_type').val(), url = '/marks/' + report_type + '/' + obj_id + '/' + action + '/inline/';
    $.get(url, {}, function (data) {
        if (data.error) err_notify(data.error);
        else {
            container.html(data);
            if (report_type !== 'unknown') {
                activate_tags();
            }
            container.find('.ui.checkbox').checkbox();
            container.show();
            $('#close_inline_mark_form').click(function () { $('#inline_mark_form').hide().empty() });
            $('#save_inline_mark_btn').click(save_inline_mark);
            $('#progress_bar_popup').modal('setting', 'closable', false);
        }
        init_tags();
    });
};

