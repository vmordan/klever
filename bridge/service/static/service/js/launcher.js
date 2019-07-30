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

function show_config() {
    var preset_config = $('#job_type').val();
    if (preset_config && preset_config != 'other') {
        $.post(
            '/service/get_config/' + preset_config +'/',
            {},
            function (data) {
                if (data.error) {
                    err_notify(data.error);
                    return false;
                }
                $('#config_text').val(data.config);
                $('#show_config').modal('show');
            }
        );
    }
}

$(document).ready(function () {
    $('#launch_button').click(function () {
        var data = new FormData();
        $('input[id^="upload_verifier_"]').each(function () {
            var verifier_type = $(this).attr("id").replace(/^upload_verifier_/,"");
            if ($(this) && $(this)[0].files) {
                data.append('upload_verifier_' + verifier_type, $(this)[0].files[0]);
            }
        });

        var is_specific_config = false;
        var files = $('#upload_config')[0].files;
        var job_type = $('#job_type').val();
        if (job_type == "other") {
            for (var i = 0; i < files.length; i++) {
                data.append('upload_config', files[i]);
                is_specific_config = true;
            }
        }
        data.append('parent_job_id', $('#parent_job_id').val());
        data.append('new_job_name', $('#new_job_name').val());
        data.append('job_type', job_type);
        data.append('priority', $('#priority').val());
        data.append('limit_cpu_time', $('#limit_cpu_time').val());
        data.append('limit_cpu_cores', $('#limit_cpu_cores').val());
        data.append('limit_memory', $('#limit_memory').val());
        data.append('limit_cpu_time_stats', $('#limit_cpu_time_stats').val());
        data.append('job_desc', $('#job_desc').val());
        data.append('reuse_sources', $('#reuse_sources').is(':checked'));
        data.append('reuse_tools', $('#reuse_tools').is(':checked'));

        if (!$('#new_job_name').val()) {
            err_notify($('#trans__err_job_name').text());
            return;
        }
        if (!$('#parent_job_id').val()) {
            err_notify($('#trans__err_parent').text());
            return;
        }
        if (!job_type) {
            err_notify($('#trans__err_config').text());
            return;
        }
        if (job_type == "other" && !is_specific_config) {
            err_notify($('#trans__err_specific_config').text());
            return;
        }

        $(this).addClass('disabled');
        $.ajax({
            url: '/service/ajax/launch_job/',
            data: data,
            type: 'POST',
            dataType: 'json',
            contentType: false,
            processData: false,
            mimeType: 'multipart/form-data',
            xhr: function() {
                return $.ajaxSettings.xhr();
            },
            success: function (data) {
                if (data.error) {
                    err_notify(data.error);
                    $('#launch_button').removeClass('disabled');
                }
                else {
                    if (data.new_job_id) {
                        window.location.href = '/jobs/' + data.new_job_id;
                    } else {
                        err_notify("Cannot get created job id");
                        $('#launch_button').removeClass('disabled');
                    }
                }
            }
        });
    });

    $('#upload_config').on('fileselect', function () {
        $('#upload_config_filename').text($(this)[0].files[0].name);
    });
    $('input[id^="upload_verifier_"]').on('fileselect', function () {
        var property_type = $(this).attr("id").replace(/^upload_verifier_/,"");
        $('#upload_verifier_' + property_type + '_filename').text($(this)[0].files[0].name);
    });
    $('#upload_aux').on('fileselect', function () {
        var files = $(this)[0].files,
            filename_list = $('<ul>');
        for (var i = 0; i < files.length; i++) {
            filename_list.append($('<li>', {text: files[i].name}));
        }
        $('#upload_aux_filename').html(filename_list);
    });
    $('#cancel_show_config').click(function () {
        $('#show_config').modal('hide');
    });
    $('#job_type').change(function () {
        if ($('#job_type').val() == "other") {
            $('#job_type_other').show();
        } else {
            $('#job_type_other').hide();
        }

    });
});
