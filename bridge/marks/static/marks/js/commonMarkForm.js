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

function update_progress(mark_id, time_start) {
    if (!mark_id) {
        $.ajax({type: 'POST', url: '/marks/get_last_mark/', success:
            function (data) {
                if (data.error) {
                    err_notify(data.error);
                    return false;
                }
                mark_id = data['mark'];
            },
            async: false
        });
    }
    $.post(
        '/marks/get_progress/' + mark_id +'/', {},
        function (data) {
            if (data.error) {
                err_notify(data.error);
                return false;
            }
            if ($('#progress_bar').progress('get percent') < data['progress']) {
                $('#progress_bar').progress('set progress', data['progress']);
            }
            $('#progress_bar_mark_id').text(data['mark_id']);
            $('#progress_bar_mark_wall_time').text(Number((performance.now() - time_start) / 1000).toFixed(3));
            $('#progress_bar_mark_applied').text(data['applied']);
        }
    );
    return mark_id;
}
