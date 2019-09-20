/*
 * Klever-CV is a web-interface for continuous verification results visualization.
 *
 * Copyright (c) 2018-2019 ISP RAS (http://www.ispras.ru)
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

function toggle_children(parent_id) {
    $('div[id^="' + parent_id + '_"]').each(function () {
        if ($(this).is(':hidden')) {
            $(this).show();
        } else {
            $(this).hide();
        }
    });
}

function change_id_1(identifier) {
    var settings = window.location.search;
    window.location.href = '/reports/comparison/' + identifier + "/" + $('#job_id_2').val() + settings;
}

function change_id_2(identifier) {
    var settings = window.location.search;
    window.location.href = '/reports/comparison/' + $('#job_id_1').val() + "/" + identifier + settings;
}

function apply_new_settings() {
    var elems = $('input:checkbox');
    var data = {};
    var comparison_attrs = [];
    var filtered_values = [];
    var same_transitions = [];
    var lost_transitions = [];
    var diff_attrs = [];
    var selected_jobs = [];
    var mea_config = {};
    var problems_config = {};
    for (var elem in elems) {
        var id = elems[elem].id;
        if (id && elems[elem].checked && id.startsWith('cs1__')) {
            comparison_attrs.push(id.replace(/^cs1__/,""));
        }
        if (id && !elems[elem].checked && id.startsWith('cs2__')) {
            filtered_values.push(id.replace(/^cs2__/,""));
        }
        if (id && elems[elem].checked && id.startsWith('cs3__')) {
            same_transitions.push(id.replace(/^cs3__/,""));
        }
        if (id && elems[elem].checked && id.startsWith('cs4__')) {
            lost_transitions.push(id.replace(/^cs4__/,""));
        }
        if (id && elems[elem].checked && id.startsWith('cs5__')) {
            mea_config['enable'] = true;
        }
        if (id && elems[elem].checked && id.startsWith('cs6__')) {
            diff_attrs.push(id.replace(/^cs6__/,""));
        }
        if (id && elems[elem].checked && id.startsWith('cs8__')) {
            selected_jobs.push(id.replace(/^cs8__/,""));
        }
    }
    elems = $('input:radio');
    var clustering_type = "";
    var problems_type = "";
    for (var elem in elems) {
        var id = elems[elem].id;
        if (id && elems[elem].checked && id.startsWith('cs5__show_')) {
            clustering_type = id.replace(/^cs5__show_/,"");
        }
        if (id && elems[elem].checked && id.startsWith('cs7__show_')) {
            problems_type = id.replace(/^cs7__show_/,"");
        }
    }
    mea_config['enable'] = $('#cs5__auto_cluster_traces').is(':checked');
    mea_config['clustering_type'] = clustering_type;
    mea_config['conversion'] = $('#cs5__conversion_function').val();
    mea_config['comparison'] = $('#cs5__comparison_function').val();
    mea_config['similarity'] = $('#cs5__similarity_threshold').val();

    problems_config['enable'] = $('#cs7__show_problems').is(':checked');
    problems_config['show_problems_type'] = problems_type;

    data['comparison_attrs'] = comparison_attrs;
    data['filtered_values'] = filtered_values;
    data['same_transitions'] = same_transitions;
    data['lost_transitions'] = lost_transitions;
    data['diff_attrs'] = diff_attrs;
    data['mea_config'] = mea_config;
    data['problems_config'] = problems_config;
    data['selected_jobs'] = selected_jobs;
    $('#dimmer_of_page').addClass('active');
    window.location.replace(get_url_with_get_parameter(window.location.href, 'data', JSON.stringify(data)));
}

function show_converted_error_trace(conversion_function, report_id) {
    $.post(
        '/marks/get_converted_trace/' + report_id +'/',
        {
            "conversion": conversion_function
        },
        function (data) {
            if (data.error) {
                err_notify(data.error);
                return false;
            }
            $('#converted_error_trace').val(data['converted_error_trace']);
            $('#show_converted_error_trace').modal('show');
        }
    );
}

$(document).ready(function () {
    $('div[id^="acc_row_attrs_"]').children('div[class^="title"]').click(function (data) {
        $('div[id^="acc_row_attrs_"]').accordion('toggle', 0);
    });
    $('div[id^="acc_row_et_"]').children('div[class^="title"]').click(function (data) {
        $('div[id^="acc_row_et_"]').accordion('toggle', 0);
    });
    $('div[id^="acc_row_res_"]').children('div[class^="title"]').click(function (data) {
        $('div[id^="acc_row_res_"]').accordion('toggle', 0);
    });
    $('div[id^="acc_row_"]').accordion({
        selector: {
          trigger: null
        }
    });

    $('#apply_new_settings').click(function () {
        $(this).addClass('disabled');
        apply_new_settings();
    });
    $('#cancel_settings').click(function () {
        window.location.href = '/reports/comparison/' + $('#job_id_1').val() + "/" + $('#job_id_2').val();
    });
    $('#cancel_show_converted_error_trace').click(function () {
        $('#show_converted_error_trace').modal('hide');
    });
    $('#exchange').click(function () {
        var settings = window.location.search;
        window.location.href = '/reports/comparison/' + $('#job_id_2').val() + "/" + $('#job_id_1').val() + settings;
    });

    $('div[id^="settings_8_"]').each(function () {
        if (!$(this).find('input:checkbox').is(':checked')) {
            $(this).hide();
        }
    });
});
